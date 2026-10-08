#pragma once
#include "provider-module.hpp"

namespace vpn {
struct SsCipherSpec { size_t key,iv;bool stream; };
inline SsCipherSpec ss_cipher_spec(const std::string& method){
    if(method=="none"||method=="plain")return {0,0,false};
    if(method=="table")return {16,0,true};
    if(method=="rc4")return {16,0,true};
    if(method=="rc4-md5")return {16,16,true};
    if(method=="salsa20"||method=="chacha20")return {32,8,true};
    if(method=="chacha20-ietf")return {32,12,true};
    if(method=="bf-cfb"||method=="cast5-cfb"||method=="idea-cfb"||method=="rc2-cfb")return {16,8,true};
    if(method=="des-cfb")return {8,8,true};
    if(method=="seed-cfb")return {16,16,true};
    auto name=method.find("2022-blake3-")==0?method.substr(12):method;
    size_t key=name.find("-128-")!=std::string::npos?16:name.find("-192-")!=std::string::npos?24:32;
    bool stream=name.find("-cfb")!=std::string::npos||name.find("-ctr")!=std::string::npos||name.find("-ofb")!=std::string::npos;
    return {key,stream?16u:name=="xchacha20-ietf-poly1305"?24u:12u,stream};
}
class SsStreamCipher {
    uint64_t id_=0;
    struct API {
        uint64_t(*create)(char*,int,char*,int,char*,int,int)=nullptr;
        int(*apply)(uint64_t,char*,int,char*,int)=nullptr;
        void(*free)(uint64_t)=nullptr;
        API(){auto& m=ProviderModule::instance();m.symbol(create,"vpn_crypto_stream_new");m.symbol(apply,"vpn_crypto_stream_apply");m.symbol(free,"vpn_crypto_stream_free");}
        static API& get(){static API api;return api;}
    };
    static char* data(const Bytes& b){return reinterpret_cast<char*>(const_cast<uint8_t*>(b.data()));}
public:
    SsStreamCipher()=default;SsStreamCipher(const SsStreamCipher&)=delete;SsStreamCipher& operator=(const SsStreamCipher&)=delete;
    ~SsStreamCipher(){if(id_)API::get().free(id_);}
    void start(const std::string& method,const Bytes& key,const Bytes& iv,bool decrypt=false){
        if(id_)throw Failure("CRYPTO_FAILED: duplicate stream initialization","SS_STREAM_STATE");
        id_=API::get().create(const_cast<char*>(method.data()),int(method.size()),data(key),int(key.size()),data(iv),int(iv.size()),decrypt?1:0);
        if(!id_)throw Failure("CRYPTO_FAILED: stream initialization","SS_STREAM_INITIALIZATION");
    }
    Bytes apply(const Bytes& in){if(!id_||in.size()>1048576)throw Failure("CRYPTO_FAILED: stream state or size","SS_STREAM_STATE");Bytes out(in.size());auto n=API::get().apply(id_,data(in),int(in.size()),data(out),int(out.size()));if(n!=int(in.size()))throw Failure("CRYPTO_FAILED: stream operation","SS_STREAM_CIPHER");return out;}
};
}
