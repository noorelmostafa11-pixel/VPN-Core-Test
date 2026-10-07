#pragma once
// Test-only CNG contract double: retains and touches object storage until
// DestroyHash/DestroyKey. ASan catches early frees in the production branch.
// OpenSSL is an independent oracle, never a Windows production dependency.
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cwchar>
#include <cstring>
#include <memory>
using ULONG=uint32_t;using PUCHAR=unsigned char*;using NTSTATUS=int32_t;
inline constexpr wchar_t BCRYPT_MD5_ALGORITHM[]=L"MD5",BCRYPT_SHA1_ALGORITHM[]=L"SHA1",BCRYPT_SHA256_ALGORITHM[]=L"SHA256",BCRYPT_SHA384_ALGORITHM[]=L"SHA384",BCRYPT_SHA512_ALGORITHM[]=L"SHA512",BCRYPT_AES_ALGORITHM[]=L"AES",BCRYPT_HASH_LENGTH[]=L"HashDigestLength",BCRYPT_OBJECT_LENGTH[]=L"ObjectLength",BCRYPT_CHAINING_MODE[]=L"ChainingMode",BCRYPT_CHAIN_MODE_ECB[]=L"ChainingModeECB",BCRYPT_CHAIN_MODE_GCM[]=L"ChainingModeGCM";
inline constexpr ULONG BCRYPT_USE_SYSTEM_PREFERRED_RNG=2;
struct FakeAlg {const EVP_MD* md=nullptr;bool ecb=false;};
struct FakeHash {EVP_MD_CTX* context=nullptr;PUCHAR storage=nullptr;std::unique_ptr<unsigned char[]> owned;};
struct FakeKey {std::vector<uint8_t> bytes;bool ecb=false;PUCHAR storage=nullptr;std::unique_ptr<unsigned char[]> owned;};
using BCRYPT_ALG_HANDLE=FakeAlg*;using BCRYPT_HASH_HANDLE=FakeHash*;using BCRYPT_KEY_HANDLE=FakeKey*;
struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {PUCHAR pbNonce=nullptr;ULONG cbNonce=0;PUCHAR pbAuthData=nullptr;ULONG cbAuthData=0;PUCHAR pbTag=nullptr;ULONG cbTag=0;};
#define BCRYPT_INIT_AUTH_MODE_INFO(info) (info=BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO{})
inline int fake_cng_fail=0,fake_cng_live_hashes=0,fake_cng_live_keys=0,fake_cng_live_algorithms=0;
inline NTSTATUS BCryptGenRandom(void*,PUCHAR output,ULONG size,ULONG){return RAND_bytes(output,int(size))==1?0:-1;}
inline NTSTATUS BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE* result,const wchar_t* name,void*,ULONG){auto a=new FakeAlg;std::string text;while(*name)text+=char(*name++);if(text!="AES"){a->md=EVP_get_digestbyname(text.c_str());if(!a->md){delete a;return -1;}}*result=a;++fake_cng_live_algorithms;return 0;}
inline NTSTATUS BCryptGetProperty(BCRYPT_ALG_HANDLE a,const wchar_t* property,PUCHAR output,ULONG size,ULONG* used,ULONG){if(size!=sizeof(ULONG))return -1;ULONG value=std::wcscmp(property,BCRYPT_HASH_LENGTH)==0?ULONG(EVP_MD_size(a->md)):64;std::memcpy(output,&value,sizeof(value));*used=sizeof(value);return 0;}
inline NTSTATUS BCryptSetProperty(BCRYPT_ALG_HANDLE a,const wchar_t*,PUCHAR value,ULONG,ULONG){a->ecb=std::wcscmp(reinterpret_cast<wchar_t*>(value),BCRYPT_CHAIN_MODE_ECB)==0;return 0;}
inline NTSTATUS BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE a,ULONG){delete a;--fake_cng_live_algorithms;return 0;}
inline void fake_cng_storage(PUCHAR caller,ULONG size,PUCHAR& storage,std::unique_ptr<unsigned char[]>& owned){if(!caller&&!size){owned=std::make_unique<unsigned char[]>(64);storage=owned.get();}else{if(!caller||size<64)throw std::runtime_error("CNG object storage contract");storage=caller;}storage[0]=0x5a;}
inline NTSTATUS BCryptCreateHash(BCRYPT_ALG_HANDLE a,BCRYPT_HASH_HANDLE* result,PUCHAR object,ULONG size,PUCHAR,ULONG,ULONG){auto h=new FakeHash;fake_cng_storage(object,size,h->storage,h->owned);h->context=EVP_MD_CTX_new();if(!h->context||EVP_DigestInit_ex(h->context,a->md,nullptr)!=1){delete h;return -1;}*result=h;++fake_cng_live_hashes;return 0;}
inline NTSTATUS BCryptHashData(BCRYPT_HASH_HANDLE h,PUCHAR data,ULONG size,ULONG){if(fake_cng_fail==1)return -1;return EVP_DigestUpdate(h->context,data,size)==1?0:-1;}
inline NTSTATUS BCryptFinishHash(BCRYPT_HASH_HANDLE h,PUCHAR output,ULONG size,ULONG){if(fake_cng_fail==2)return -1;unsigned n=0;return EVP_DigestFinal_ex(h->context,output,&n)==1&&n==size?0:-1;}
inline NTSTATUS BCryptDestroyHash(BCRYPT_HASH_HANDLE h){volatile unsigned char value=h->storage[0];h->storage[0]=uint8_t(value^0x5a);EVP_MD_CTX_free(h->context);delete h;--fake_cng_live_hashes;return 0;}
inline NTSTATUS BCryptGenerateSymmetricKey(BCRYPT_ALG_HANDLE a,BCRYPT_KEY_HANDLE* result,PUCHAR object,ULONG size,PUCHAR secret,ULONG length,ULONG){auto k=new FakeKey;fake_cng_storage(object,size,k->storage,k->owned);k->bytes.assign(secret,secret+length);k->ecb=a->ecb;*result=k;++fake_cng_live_keys;return 0;}
inline NTSTATUS BCryptDestroyKey(BCRYPT_KEY_HANDLE k){volatile unsigned char value=k->storage[0];k->storage[0]=uint8_t(value^0x5a);delete k;--fake_cng_live_keys;return 0;}
inline NTSTATUS fake_cng_cipher(BCRYPT_KEY_HANDLE k,PUCHAR data,ULONG size,void* padding,PUCHAR output,ULONG capacity,ULONG* produced,bool decrypt){
    if(fake_cng_fail==3)return -1;
    const EVP_CIPHER* cipher=k->ecb?(k->bytes.size()==16?EVP_aes_128_ecb():k->bytes.size()==24?EVP_aes_192_ecb():EVP_aes_256_ecb()):(k->bytes.size()==16?EVP_aes_128_gcm():k->bytes.size()==24?EVP_aes_192_gcm():EVP_aes_256_gcm());
    auto c=EVP_CIPHER_CTX_new();struct Guard{EVP_CIPHER_CTX* c;~Guard(){EVP_CIPHER_CTX_free(c);}}guard{c};
    auto info=static_cast<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO*>(padding);int n=0,tail=0;
    if(capacity<size+16||EVP_CipherInit_ex(c,cipher,nullptr,k->bytes.data(),info?info->pbNonce:nullptr,decrypt?0:1)!=1||EVP_CIPHER_CTX_set_padding(c,0)!=1)return -1;
    if(info&&info->cbAuthData&&EVP_CipherUpdate(c,nullptr,&n,info->pbAuthData,int(info->cbAuthData))!=1)return -1;
    if(EVP_CipherUpdate(c,output,&n,data,int(size))!=1)return -1;
    if(info&&decrypt&&EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_TAG,int(info->cbTag),info->pbTag)!=1)return -1;
    if(EVP_CipherFinal_ex(c,output+n,&tail)!=1)return -1;
    if(info&&!decrypt&&EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_GET_TAG,int(info->cbTag),info->pbTag)!=1)return -1;
    *produced=ULONG(n+tail);return 0;
}
inline NTSTATUS BCryptEncrypt(BCRYPT_KEY_HANDLE k,PUCHAR data,ULONG size,void* padding,PUCHAR,ULONG,PUCHAR output,ULONG capacity,ULONG* produced,ULONG){return fake_cng_cipher(k,data,size,padding,output,capacity,produced,false);}
inline NTSTATUS BCryptDecrypt(BCRYPT_KEY_HANDLE k,PUCHAR data,ULONG size,void* padding,PUCHAR,ULONG,PUCHAR output,ULONG capacity,ULONG* produced,ULONG){return fake_cng_cipher(k,data,size,padding,output,capacity,produced,true);}
