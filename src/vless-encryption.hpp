#pragma once
#include "provider-module.hpp"
namespace vpn {
struct VlessEncryptionAPI {
    uint64_t(*create)(char*,int)=nullptr;int(*validate)(char*,int)=nullptr;int(*feed)(uint64_t,char*,int)=nullptr;int(*write)(uint64_t,char*,int)=nullptr;int(*read)(uint64_t,int,char*,int)=nullptr;int(*state)(uint64_t)=nullptr;int(*pending)(uint64_t)=nullptr;int(*finish)(uint64_t)=nullptr;void(*free)(uint64_t)=nullptr;
    VlessEncryptionAPI(){auto& api=ProviderModule::instance();api.symbol(create,"vpn_vless_enc_new");api.symbol(validate,"vpn_vless_enc_validate");api.symbol(feed,"vpn_vless_enc_feed");api.symbol(write,"vpn_vless_enc_write");api.symbol(read,"vpn_vless_enc_read");api.symbol(state,"vpn_vless_enc_state");api.symbol(pending,"vpn_vless_enc_pending");api.symbol(finish,"vpn_vless_enc_finish");api.symbol(free,"vpn_vless_enc_free");}
    static VlessEncryptionAPI& instance(){static VlessEncryptionAPI api;return api;}
};
inline bool vless_encryption_supported(const Config& c){if(c.encryption=="none")return true;if(c.encryption.find("mlkem768x25519plus.")!=0)return false;auto text=c.encryption;if(VlessEncryptionAPI::instance().validate(text.data(),int(text.size()))!=0)throw Failure("PARSE_INVALID: VLESS encryption configuration","VLESS_ENCRYPTION_CONFIGURATION");return true;}
class VlessEncryption {
    const Config& c_;VlessEncryptionAPI* api_=nullptr;uint64_t id_=0;
    void check()const{if(id_&&api_->state(id_)<0)throw Failure("PROTOCOL_FAILED: VLESS encryption authentication failed","VLESS_ENCRYPTION_AUTHENTICATION",uint32_t(-api_->state(id_)));}
    Bytes drain(int kind){check();Bytes out;if(!id_)return out;char data[65536];for(;;){int n=api_->read(id_,kind,data,sizeof(data));if(n<0)throw Failure("PROTOCOL_FAILED: VLESS encryption read","VLESS_ENCRYPTION_READ");if(!n)break;out.insert(out.end(),reinterpret_cast<uint8_t*>(data),reinterpret_cast<uint8_t*>(data)+n);if(out.size()>1048576)throw Failure("PROTOCOL_FAILED: VLESS encryption buffer limit","VLESS_ENCRYPTION_LIMIT");}return out;}
public:
    explicit VlessEncryption(const Config& c):c_(c){}~VlessEncryption(){if(id_)api_->free(id_);}
    VlessEncryption(const VlessEncryption&)=delete;VlessEncryption& operator=(const VlessEncryption&)=delete;
    Bytes open(const Bytes& plain){if(c_.encryption=="none")return plain;api_=&VlessEncryptionAPI::instance();Json j=Json::obj();j["encryption"]=Json(c_.encryption);j["timeout_ms"]=Json::integer(c_.connect_ms);auto text=json_dump(j);id_=api_->create(text.data(),int(text.size()));if(!id_)throw Failure("PARSE_INVALID: VLESS encryption configuration","VLESS_ENCRYPTION_CONFIGURATION");return encode(plain);}
    Bytes encode(const Bytes& plain){if(!id_)return plain;check();for(size_t p=0;p<plain.size();p+=16384){auto n=std::min(size_t(16384),plain.size()-p);if(api_->write(id_,reinterpret_cast<char*>(const_cast<uint8_t*>(plain.data()+p)),int(n))!=int(n))throw Failure("PROTOCOL_FAILED: VLESS encryption write buffer","VLESS_ENCRYPTION_LIMIT");}return drain(0);}
    Bytes decode(const Bytes& wire){if(!id_)return wire;check();for(size_t p=0;p<wire.size();p+=65536){auto n=std::min(size_t(65536),wire.size()-p);if(api_->feed(id_,reinterpret_cast<char*>(const_cast<uint8_t*>(wire.data()+p)),int(n))<0){check();throw Failure("PROTOCOL_FAILED: VLESS encryption input","VLESS_ENCRYPTION_INPUT");}}return drain(1);}
    Bytes control(){return drain(0);}
    size_t pending(){if(!id_)return 0;check();auto n=api_->pending(id_);return n<0?0:size_t(n);}
    bool closed()const{check();return id_&&api_->state(id_)==2;}
    void finish(){if(id_&&api_->finish(id_)<0){check();throw Failure("PROTOCOL_FAILED: VLESS encryption EOF","VLESS_ENCRYPTION_EOF");}}
};
}
