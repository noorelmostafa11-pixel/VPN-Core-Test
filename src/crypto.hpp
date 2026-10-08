#pragma once
#include <utility>
#include "config.hpp"
#include <functional>
#if defined(VPN_CORE_CNG_TEST)
#include "../tests/fake_cng.hpp"
#elif defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#elif defined(VPN_CORE_PORTABLE)
#include "portable-crypto.hpp"
#else
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

namespace vpn {
inline Bytes random_bytes(size_t n){Bytes b(n);
#if defined(_WIN32) || defined(VPN_CORE_CNG_TEST)
    if(BCryptGenRandom(nullptr,b.data(),ULONG(n),BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)throw std::runtime_error("CRYPTO_FAILED: operating-system RNG");
#elif defined(VPN_CORE_PORTABLE)
    if(PortableCrypto::instance().random(PortableCrypto::data(b),PortableCrypto::size(n))!=0)throw Failure("CRYPTO_FAILED: random generator","CRYPTO_RANDOM");
#else
    if(RAND_bytes(b.data(),int(n))!=1)throw std::runtime_error("CRYPTO_FAILED: test RNG");
#endif
    return b;}
inline Bytes digest(const std::string& algorithm,const Bytes& data){
#if defined(_WIN32) || defined(VPN_CORE_CNG_TEST)
    const wchar_t* name=algorithm=="md5"?BCRYPT_MD5_ALGORITHM:algorithm=="sha1"?BCRYPT_SHA1_ALGORITHM:algorithm=="sha256"?BCRYPT_SHA256_ALGORITHM:algorithm=="sha384"?BCRYPT_SHA384_ALGORITHM:algorithm=="sha512"?BCRYPT_SHA512_ALGORITHM:nullptr;if(!name)throw std::runtime_error("CRYPTO_FAILED: unknown digest");
    BCRYPT_ALG_HANDLE alg=nullptr;BCRYPT_HASH_HANDLE hash=nullptr;struct Guard{BCRYPT_ALG_HANDLE& a;BCRYPT_HASH_HANDLE& h;~Guard(){if(h)BCryptDestroyHash(h);if(a)BCryptCloseAlgorithmProvider(a,0);}}guard{alg,hash};
    ULONG hash_size=0,used=0;
    if(BCryptOpenAlgorithmProvider(&alg,name,nullptr,0)<0||BCryptGetProperty(alg,BCRYPT_HASH_LENGTH,reinterpret_cast<PUCHAR>(&hash_size),sizeof(hash_size),&used,0)<0)throw std::runtime_error("CRYPTO_FAILED: digest initialization");
    // Let CNG own its object storage until BCryptDestroyHash. A caller buffer
    // declared after Guard would be freed before Guard destroyed the handle.
    Bytes out(hash_size);if(BCryptCreateHash(alg,&hash,nullptr,0,nullptr,0,0)<0||BCryptHashData(hash,const_cast<PUCHAR>(data.data()),ULONG(data.size()),0)<0||BCryptFinishHash(hash,out.data(),hash_size,0)<0)throw std::runtime_error("CRYPTO_FAILED: digest");return out;
#elif defined(VPN_CORE_PORTABLE)
    const std::map<std::string,int> kinds{{"md5",1},{"sha1",2},{"sha256",3},{"sha384",4},{"sha512",5}};auto k=kinds.find(algorithm);if(k==kinds.end())throw Failure("CRYPTO_FAILED: unknown digest","CRYPTO_DIGEST");Bytes out(64);int n=PortableCrypto::instance().hash(k->second,PortableCrypto::data(data),PortableCrypto::size(data.size()),PortableCrypto::data(out),int(out.size()));if(n<=0||n>int(out.size()))throw Failure("CRYPTO_FAILED: digest","CRYPTO_DIGEST");out.resize(size_t(n));return out;
#else
    auto md=EVP_get_digestbyname(algorithm.c_str());if(!md)throw std::runtime_error("CRYPTO_FAILED: digest unavailable");Bytes out(size_t(EVP_MD_size(md)));unsigned n=0;if(EVP_Digest(data.data(),data.size(),out.data(),&n,md,nullptr)!=1)throw std::runtime_error("CRYPTO_FAILED: digest");out.resize(n);return out;
#endif
}
using HashFunction=std::function<Bytes(const Bytes&)>;
inline Bytes hmac_with(const HashFunction& hash,Bytes key,const Bytes& data,size_t block=64){if(key.size()>block)key=hash(key);key.resize(block);Bytes inner=key,outer=key;for(auto& b:inner)b^=0x36;for(auto& b:outer)b^=0x5c;inner.insert(inner.end(),data.begin(),data.end());auto d=hash(inner);outer.insert(outer.end(),d.begin(),d.end());return hash(outer);}
inline Bytes hmac(const std::string& algorithm,const Bytes& key,const Bytes& data){return hmac_with([&](const Bytes& b){return digest(algorithm,b);},key,data,algorithm=="sha384"||algorithm=="sha512"?128:64);}
inline Bytes hkdf_sha1(const Bytes& key,const Bytes& salt,const Bytes& info,size_t n){auto prk=hmac("sha1",salt,key);Bytes t,o;for(unsigned i=1;o.size()<n;++i){Bytes m=t;m.insert(m.end(),info.begin(),info.end());m.push_back(uint8_t(i));t=hmac("sha1",prk,m);o.insert(o.end(),t.begin(),t.end());}o.resize(n);return o;}
inline Bytes vmess_kdf(const Bytes& key,const std::vector<Bytes>& paths){HashFunction f=[](const Bytes& b){return digest("sha256",b);};std::vector<Bytes> keys{to_bytes("VMess AEAD KDF")};keys.insert(keys.end(),paths.begin(),paths.end());for(const auto& k:keys){auto prior=f;f=[prior,k](const Bytes& b){return hmac_with(prior,k,b);};}return f(key);}
inline Bytes first(Bytes b,size_t n){if(b.size()<n)throw std::runtime_error("CRYPTO_FAILED: truncated digest");b.resize(n);return b;}
inline bool equal_bytes(const Bytes& a,const Bytes& b){if(a.size()!=b.size())return false;uint8_t x=0;for(size_t i=0;i<a.size();++i)x|=a[i]^b[i];return x==0;}
inline uint32_t little32(const uint8_t* p){return uint32_t(p[0])|(uint32_t(p[1])<<8)|(uint32_t(p[2])<<16)|(uint32_t(p[3])<<24);}
inline void put_little32(uint8_t* p,uint32_t v){for(int i=0;i<4;++i)p[i]=uint8_t(v>>(8*i));}
inline uint32_t rotate_left(uint32_t x,unsigned n){return (x<<n)|(x>>(32-n));}
inline Bytes chacha_block(const Bytes& key,const Bytes& nonce,uint32_t count){if(key.size()!=32||nonce.size()!=12)throw std::runtime_error("CRYPTO_FAILED: invalid ChaCha parameters");std::array<uint32_t,16> initial{{0x61707865,0x3320646e,0x79622d32,0x6b206574}};for(unsigned i=0;i<8;++i)initial[4+i]=little32(key.data()+i*4);initial[12]=count;for(unsigned i=0;i<3;++i)initial[13+i]=little32(nonce.data()+i*4);auto x=initial;
    auto qr=[&](unsigned a,unsigned b,unsigned c,unsigned d){x[a]+=x[b];x[d]=rotate_left(x[d]^x[a],16);x[c]+=x[d];x[b]=rotate_left(x[b]^x[c],12);x[a]+=x[b];x[d]=rotate_left(x[d]^x[a],8);x[c]+=x[d];x[b]=rotate_left(x[b]^x[c],7);};
    for(int i=0;i<10;++i){qr(0,4,8,12);qr(1,5,9,13);qr(2,6,10,14);qr(3,7,11,15);qr(0,5,10,15);qr(1,6,11,12);qr(2,7,8,13);qr(3,4,9,14);}Bytes out(64);for(unsigned i=0;i<16;++i)put_little32(out.data()+4*i,x[i]+initial[i]);return out;}
inline Bytes chacha_xor(const Bytes& key,const Bytes& nonce,const Bytes& in){Bytes o=in;uint32_t count=1;for(size_t i=0;i<o.size();i+=64){auto block=chacha_block(key,nonce,count++);for(size_t j=0;j<64&&i+j<o.size();++j)o[i+j]^=block[j];}return o;}
// Project-owned Poly1305 arithmetic, radix 2^26; reduction uses 2^130 == 5.
inline Bytes poly1305(const Bytes& key,const Bytes& data){if(key.size()!=32)throw std::runtime_error("CRYPTO_FAILED: Poly1305 key size");Bytes rbytes(key.begin(),key.begin()+16);for(unsigned i:{3u,7u,11u,15u})rbytes[i]&=15;for(unsigned i:{4u,8u,12u})rbytes[i]&=252;
    constexpr uint64_t mask=(uint64_t(1)<<26)-1;std::array<uint64_t,5> r{},h{};
    auto limbs=[](const Bytes& b){std::array<uint64_t,5> v{};for(size_t i=0;i<b.size();++i)for(unsigned k=0;k<8;++k)if(b[i]&(1u<<k)){size_t bit=i*8+k;if(bit<130)v[bit/26]|=uint64_t(1)<<(bit%26);}return v;};r=limbs(rbytes);
    for(size_t pos=0;pos<data.size();pos+=16){size_t n=std::min(size_t(16),data.size()-pos);Bytes b(data.begin()+std::ptrdiff_t(pos),data.begin()+std::ptrdiff_t(pos+n));b.push_back(1);auto m=limbs(b);for(unsigned i=0;i<5;++i)h[i]+=m[i];std::array<uint64_t,5> product{};
        for(unsigned i=0;i<5;++i)for(unsigned j=0;j<5;++j){unsigned p=i+j;product[p%5]+=h[i]*r[j]*(p>=5?5:1);}h=product;
        for(unsigned loop=0;loop<3;++loop){for(unsigned i=0;i<4;++i){h[i+1]+=h[i]>>26;h[i]&=mask;}uint64_t carry=h[4]>>26;h[4]&=mask;h[0]+=carry*5;}}
    for(unsigned loop=0;loop<3;++loop){for(unsigned i=0;i<4;++i){h[i+1]+=h[i]>>26;h[i]&=mask;}auto carry=h[4]>>26;h[4]&=mask;h[0]+=carry*5;}
    std::array<uint64_t,5> prime{{mask-4,mask,mask,mask,mask}};bool ge=true;for(int i=4;i>=0;--i)if(h[size_t(i)]!=prime[size_t(i)]){ge=h[size_t(i)]>prime[size_t(i)];break;}
    if(ge){uint64_t borrow=0;for(unsigned i=0;i<5;++i){uint64_t sub=prime[i]+borrow;borrow=h[i]<sub;h[i]=(h[i]-sub)&mask;}}
    Bytes tag(16);for(unsigned i=0;i<16;++i)for(unsigned k=0;k<8;++k){unsigned bit=i*8+k;if(h[bit/26]&(uint64_t(1)<<(bit%26)))tag[i]|=uint8_t(1u<<k);}unsigned carry=0;for(unsigned i=0;i<16;++i){unsigned v=unsigned(tag[i])+key[16+i]+carry;tag[i]=uint8_t(v);carry=v>>8;}return tag;}
inline Bytes chacha_tag(const Bytes& key,const Bytes& nonce,const Bytes& aad,const Bytes& cipher){auto k=first(chacha_block(key,nonce,0),32);Bytes mac=aad;while(mac.size()%16)mac.push_back(0);mac.insert(mac.end(),cipher.begin(),cipher.end());while(mac.size()%16)mac.push_back(0);for(auto n:{uint64_t(aad.size()),uint64_t(cipher.size())})for(unsigned i=0;i<8;++i)mac.push_back(uint8_t(n>>(8*i)));return poly1305(k,mac);}
inline Bytes aes(const Bytes& key,const Bytes& nonce,const Bytes& input,const Bytes& aad,bool decrypt,bool ecb=false){
#if defined(_WIN32) || defined(VPN_CORE_CNG_TEST)
    BCRYPT_ALG_HANDLE alg=nullptr;BCRYPT_KEY_HANDLE handle=nullptr;struct Guard{BCRYPT_ALG_HANDLE& a;BCRYPT_KEY_HANDLE& k;~Guard(){if(k)BCryptDestroyKey(k);if(a)BCryptCloseAlgorithmProvider(a,0);}}guard{alg,handle};
    if(BCryptOpenAlgorithmProvider(&alg,BCRYPT_AES_ALGORITHM,nullptr,0)<0)throw std::runtime_error("CRYPTO_FAILED: AES provider");const wchar_t* mode=ecb?BCRYPT_CHAIN_MODE_ECB:BCRYPT_CHAIN_MODE_GCM;ULONG mode_bytes=ULONG((wcslen(mode)+1)*sizeof(wchar_t));if(BCryptSetProperty(alg,BCRYPT_CHAINING_MODE,reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(mode)),mode_bytes,0)<0)throw std::runtime_error("CRYPTO_FAILED: AES mode");
    // CNG allocates and releases key-object storage with the key handle.
    if(BCryptGenerateSymmetricKey(alg,&handle,nullptr,0,const_cast<PUCHAR>(key.data()),ULONG(key.size()),0)<0)throw std::runtime_error("CRYPTO_FAILED: AES key");
    Bytes data=input,tag(16);BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;BCRYPT_INIT_AUTH_MODE_INFO(info);void* padding=nullptr;
    if(!ecb){if(nonce.size()!=12)throw std::runtime_error("CRYPTO_FAILED: AES nonce");if(decrypt){if(data.size()<16)throw Failure("PROTOCOL_FAILED: truncated AEAD tag","AEAD_TAG_TRUNCATED");std::copy(data.end()-16,data.end(),tag.begin());data.resize(data.size()-16);}info.pbNonce=const_cast<PUCHAR>(nonce.data());info.cbNonce=ULONG(nonce.size());info.pbAuthData=const_cast<PUCHAR>(aad.data());info.cbAuthData=ULONG(aad.size());info.pbTag=tag.data();info.cbTag=ULONG(tag.size());padding=&info;}
    Bytes out(data.size()+16);ULONG produced=0;auto status=decrypt?BCryptDecrypt(handle,data.data(),ULONG(data.size()),padding,nullptr,0,out.data(),ULONG(out.size()),&produced,0):BCryptEncrypt(handle,data.data(),ULONG(data.size()),padding,nullptr,0,out.data(),ULONG(out.size()),&produced,0);
    if(status<0){if(decrypt)throw Failure("PROTOCOL_FAILED: AEAD authentication failed","AEAD_AUTHENTICATION",uint32_t(status));throw Failure("CRYPTO_FAILED: AES encryption","AES_ENCRYPTION",uint32_t(status));}out.resize(produced);if(!ecb&&!decrypt)out.insert(out.end(),tag.begin(),tag.end());return out;
#elif defined(VPN_CORE_PORTABLE)
    Bytes out(input.size()+32);int n=PortableCrypto::instance().cipher(PortableCrypto::data(key),PortableCrypto::size(key.size()),PortableCrypto::data(nonce),PortableCrypto::size(nonce.size()),PortableCrypto::data(input),PortableCrypto::size(input.size()),PortableCrypto::data(aad),PortableCrypto::size(aad.size()),int(decrypt),int(ecb),PortableCrypto::data(out),PortableCrypto::size(out.size()));if(n<0)throw Failure("PROTOCOL_FAILED: AEAD verification or parameters failed",decrypt?"AEAD_AUTHENTICATION":"AES_ENCRYPTION");if(size_t(n)>out.size())throw Failure("CRYPTO_FAILED: result limit","CRYPTO_OUTPUT_LIMIT");out.resize(size_t(n));return out;
#else
    auto cipher=ecb?(key.size()==16?EVP_aes_128_ecb():key.size()==24?EVP_aes_192_ecb():EVP_aes_256_ecb()):(key.size()==16?EVP_aes_128_gcm():key.size()==24?EVP_aes_192_gcm():EVP_aes_256_gcm());EVP_CIPHER_CTX* context=EVP_CIPHER_CTX_new();if(!context)throw std::runtime_error("CRYPTO_FAILED: test AES allocation");struct Guard{EVP_CIPHER_CTX* c;~Guard(){EVP_CIPHER_CTX_free(c);}}guard{context};Bytes data=input,tag(16),out(data.size()+32);int produced=0,tail=0;
    if(decrypt&&!ecb){if(data.size()<16)throw Failure("PROTOCOL_FAILED: truncated AEAD tag","AEAD_TAG_TRUNCATED");std::copy(data.end()-16,data.end(),tag.begin());data.resize(data.size()-16);}
    if(EVP_CipherInit_ex(context,cipher,nullptr,key.data(),ecb?nullptr:nonce.data(),decrypt?0:1)!=1||EVP_CIPHER_CTX_set_padding(context,0)!=1)throw std::runtime_error("CRYPTO_FAILED: test AES initialization");
    if(!ecb&&!aad.empty()){int n=0;if(EVP_CipherUpdate(context,nullptr,&n,aad.data(),int(aad.size()))!=1)throw std::runtime_error("CRYPTO_FAILED: test AES AAD");}
    if(EVP_CipherUpdate(context,out.data(),&produced,data.data(),int(data.size()))!=1)throw std::runtime_error("CRYPTO_FAILED: test AES data");if(decrypt&&!ecb&&EVP_CIPHER_CTX_ctrl(context,EVP_CTRL_GCM_SET_TAG,16,tag.data())!=1)throw std::runtime_error("CRYPTO_FAILED: test AES tag");
    if(EVP_CipherFinal_ex(context,out.data()+produced,&tail)!=1)throw Failure("PROTOCOL_FAILED: AEAD authentication failed","AEAD_AUTHENTICATION");out.resize(size_t(produced+tail));if(!ecb&&!decrypt){if(EVP_CIPHER_CTX_ctrl(context,EVP_CTRL_GCM_GET_TAG,16,tag.data())!=1)throw std::runtime_error("CRYPTO_FAILED: test AES tag");out.insert(out.end(),tag.begin(),tag.end());}return out;
#endif
}
inline Bytes hchacha_key(const Bytes& key,const Bytes& nonce){if(key.size()!=32||nonce.size()!=16)throw Failure("CRYPTO_FAILED: HChaCha parameters","HCHACHA_PARAMETERS");std::array<uint32_t,16> x{{0x61707865,0x3320646e,0x79622d32,0x6b206574}};for(unsigned i=0;i<8;++i)x[4+i]=little32(key.data()+i*4);for(unsigned i=0;i<4;++i)x[12+i]=little32(nonce.data()+i*4);auto qr=[&](unsigned a,unsigned b,unsigned c,unsigned d){x[a]+=x[b];x[d]=rotate_left(x[d]^x[a],16);x[c]+=x[d];x[b]=rotate_left(x[b]^x[c],12);x[a]+=x[b];x[d]=rotate_left(x[d]^x[a],8);x[c]+=x[d];x[b]=rotate_left(x[b]^x[c],7);};for(unsigned i=0;i<10;++i){qr(0,4,8,12);qr(1,5,9,13);qr(2,6,10,14);qr(3,7,11,15);qr(0,5,10,15);qr(1,6,11,12);qr(2,7,8,13);qr(3,4,9,14);}Bytes out(32);for(unsigned i=0;i<4;++i){put_little32(out.data()+i*4,x[i]);put_little32(out.data()+(i+4)*4,x[i+12]);}return out;}
inline Bytes aead(const std::string& method,const Bytes& key,const Bytes& nonce,const Bytes& input,const Bytes& aad={},bool decrypt=false){if(method=="xchacha20-ietf-poly1305"){if(nonce.size()!=24)throw Failure("CRYPTO_FAILED: XChaCha nonce","XCHACHA_NONCE");auto subkey=hchacha_key(key,Bytes(nonce.begin(),nonce.begin()+16));Bytes subnonce(4);subnonce.insert(subnonce.end(),nonce.begin()+16,nonce.end());return aead("chacha20-ietf-poly1305",subkey,subnonce,input,aad,decrypt);}if(method=="chacha20-ietf-poly1305"||method=="chacha20-poly1305"){if(decrypt){if(input.size()<16)throw Failure("PROTOCOL_FAILED: truncated ChaCha tag","AEAD_TAG_TRUNCATED");Bytes cipher(input.begin(),input.end()-16),tag(input.end()-16,input.end());if(!equal_bytes(tag,chacha_tag(key,nonce,aad,cipher)))throw Failure("PROTOCOL_FAILED: AEAD authentication failed","AEAD_AUTHENTICATION");return chacha_xor(key,nonce,cipher);}auto out=chacha_xor(key,nonce,input);auto tag=chacha_tag(key,nonce,aad,out);out.insert(out.end(),tag.begin(),tag.end());return out;}return aes(key,nonce,input,aad,decrypt);}
class AesCfb {
    Bytes key_,feedback_,block_;size_t offset_=0;std::string mode_="cfb";
public:
    void start(const Bytes& key,const Bytes& iv,const std::string& mode="cfb"){mode_=mode;if(mode!="cfb"&&mode!="ctr"&&mode!="ofb")throw std::runtime_error("CRYPTO_FAILED: AES stream mode");if(iv.size()!=16||(key.size()!=16&&key.size()!=24&&key.size()!=32))throw std::runtime_error("CRYPTO_FAILED: AES-CFB parameters");key_=key;feedback_=iv;block_.clear();offset_=0;}
    Bytes apply(const Bytes& input,bool decrypt=false){if(feedback_.size()!=16)throw std::runtime_error("CRYPTO_FAILED: AES-CFB not initialized");Bytes output=input;for(size_t i=0;i<input.size();++i){if(offset_==0){block_=aes(key_,{},feedback_,{},false,true);if(mode_=="ofb")feedback_=block_;else if(mode_=="ctr"){for(size_t n=16;n>0;--n)if(++feedback_[n-1])break;}}output[i]^=block_[offset_];if(mode_=="cfb")feedback_[offset_]=decrypt?input[i]:output[i];offset_=(offset_+1)%16;}return output;}
};
inline std::string hex_bytes(const Bytes& b){std::string o;const char* h="0123456789abcdef";for(auto x:b){o+=h[x>>4];o+=h[x&15];}return o;}
}
