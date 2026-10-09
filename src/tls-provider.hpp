#pragma once
#ifndef _WIN32
#include <dlfcn.h>
#endif
#include <thread>


#include "tls-options.hpp"
#include "provider-module.hpp"
namespace vpn {
struct TlsProviderAPI {
    uint64_t(*create)(char*,int)=nullptr;int(*feed)(uint64_t,char*,int)=nullptr;int(*write)(uint64_t,char*,int)=nullptr;int(*read)(uint64_t,int,char*,int)=nullptr;int(*state)(uint64_t)=nullptr;int(*info)(uint64_t,char*,int)=nullptr;int(*ready_input)(uint64_t)=nullptr;int(*shutdown)(uint64_t)=nullptr;void(*free)(uint64_t)=nullptr;
    template<class T>void symbol(T& pointer,const char* name){ProviderModule::instance().symbol(pointer,name);}
    TlsProviderAPI(){bind();}
    void bind(){symbol(create,"vpn_tls_new");symbol(feed,"vpn_tls_feed");symbol(write,"vpn_tls_write");symbol(read,"vpn_tls_read");symbol(state,"vpn_tls_state");symbol(info,"vpn_tls_info");symbol(ready_input,"vpn_tls_ready_input");symbol(shutdown,"vpn_tls_shutdown");symbol(free,"vpn_tls_free");}
    static TlsProviderAPI& instance(){static TlsProviderAPI api;return api;}
};
inline Json provider_settings(const Config& c){Json settings=Json::obj();settings["security"]=Json(c.security=="xtls"?"tls":c.security);settings["ca_pem"]=Json(c.tls_ca_pem);settings["only_custom_roots"]=Json::boolean(c.tls_only_custom_roots);settings["legacy_xtls"]=Json(c.security=="xtls"?c.flow.substr(0,c.flow.find("-udp443")):"");settings["fingerprint"]=Json(c.fingerprint.empty()&&c.security=="tls"?"native":c.fingerprint);settings["server_name"]=Json(c.tls_name);settings["public_key"]=Json(c.public_key);settings["short_id"]=Json(c.short_id);settings["pq_verify"]=Json(option(c.original_options,{"pqv","mldsa65verify","mldsa65-verify"}));settings["vision"]=Json::boolean(c.flow=="xtls-rprx-vision"||c.flow=="xtls-rprx-vision-udp443");settings["ech"]=Json(c.ech);settings["timeout_ms"]=Json::integer(c.connect_ms);settings["alpn"]=Json::arr();for(const auto& p:tls_protocols(c))settings["alpn"].array.emplace_back(p);settings["pins"]=Json::arr();for(const auto& p:certificate_pins(c))settings["pins"].array.emplace_back(p);settings["names"]=Json::arr();for(const auto& p:certificate_names(c))settings["names"].array.emplace_back(p);
#ifdef VPN_CORE_TEST_BACKEND
settings["ca_file"]=Json(c.tls_ca_file.empty()?c.test_ca_file:c.tls_ca_file);
#else
settings["ca_file"]=Json(c.tls_ca_file);
#endif
if(c.tls_only_custom_roots)settings["ca_file"]=Json(c.tls_plugin_ca_file);
return settings;}
inline std::string tls_provider_reason(int code){switch(code){
case 301:return "TLS_PROVIDER_CONFIGURATION";case 302:return "TLS_PROFILE_CONFIGURATION";case 303:return "TLS_PROVIDER_HANDSHAKE";case 304:return "TLS_PROVIDER_RECORD";case 305:return "TLS_PROVIDER_WRITE";case 307:return "TLS_PROVIDER_LIMIT";case 308:return "REALITY_AUTHENTICATION";case 309:return "ECH_QUERY_OR_CONFIG";case 310:return "TLS_CIPHER_POLICY";case 311:return "TLS_CERTIFICATE_NAME";case 312:return "TLS_CERTIFICATE_UNTRUSTED";case 313:return "TLS_CERTIFICATE_VALIDITY";case 314:return "TLS_CERTIFICATE_INVALID";case 315:return "TLS_CERTIFICATE_PIN";case 316:return "TLS_PROVIDER_TIMEOUT";case 317:return "TLS_PEER_CLOSED";case 318:return "TLS_ALERT";case 319:return "TLS_OPERATION_CANCELLED";case 321:return "TLS_RECORD_FRAMING";case 330:return "ECH_CONFIG_ENCODING";case 331:return "ECH_RESOLVER_SYNTAX";case 332:return "ECH_LOOKUP_FAILED";case 333:return "ECH_CONFIG_MISSING";case 334:return "ECH_LOOKUP_TIMEOUT";case 335:return "ECH_RESPONSE_INVALID";case 336:return "ECH_REJECTED";case 453:return "SOCKET_PROTECTION_FAILED";case 454:return "BOOTSTRAP_DNS_FAILED";default:return "TLS_PROVIDER_HANDSHAKE";}}
class ProviderTls {
    TlsProviderAPI& api_=TlsProviderAPI::instance();uint64_t id_=0;Bytes input_;bool recordwise_=false;std::string alpn_,version_;
    void check(){auto state=api_.state(id_);if(state<0)throw Failure("TLS_FAILED: TLS provider verification/record failure",tls_provider_reason(-state),uint32_t(-state));}
    Bytes drain(int kind){Bytes out;char data[65536];for(;;){int n=api_.read(id_,kind,data,sizeof(data));if(n<0)throw Failure("TLS_FAILED: TLS provider read","TLS_PROVIDER_READ");if(!n)break;out.insert(out.end(),reinterpret_cast<uint8_t*>(data),reinterpret_cast<uint8_t*>(data)+n);if(out.size()>1048576)throw Failure("TLS_FAILED: TLS provider output limit","TLS_PROVIDER_LIMIT");}return out;}
public:
    ProviderTls()=default;ProviderTls(const ProviderTls&)=delete;ProviderTls& operator=(const ProviderTls&)=delete;~ProviderTls(){if(id_)api_.free(id_);}
    void handshake(Socket& socket,const Config& c,Clock::time_point deadline){Json settings=provider_settings(c);recordwise_=c.flow=="xtls-rprx-vision"||c.flow=="xtls-rprx-vision-udp443"||c.security=="xtls";
        auto text=json_dump(settings);id_=api_.create(text.data(),int(text.size()));if(!id_)throw Failure("TLS_FAILED: provider initialization","TLS_PROVIDER_CREATE");
        for(;;){check_cancelled();auto wire=take_control();send_all(socket,wire.data(),wire.size(),deadline);check();if(api_.state(id_)!=0)break;if(Clock::now()>=deadline)throw Failure("TLS_FAILED: TLS provider timeout","TLS_PROVIDER_TIMEOUT");fd_set read;FD_ZERO(&read);FD_SET(socket.get(),&read);timeval timeout{0,1000};int r=select(int(socket.get()+1),&read,nullptr,nullptr,&timeout);if(r<0){auto error=socket_error();
#ifdef _WIN32
            if(error==WSAEINTR)continue;
#else
            if(error==EINTR)continue;
#endif
            throw Failure("TLS_FAILED: TLS provider socket wait","TLS_PROVIDER_WAIT",uint32_t(error));}if(r){auto b=receive_some(socket,deadline);for(size_t offset=0;offset<b.size();offset+=65536){auto n=std::min(size_t(65536),b.size()-offset);if(api_.feed(id_,reinterpret_cast<char*>(b.data()+offset),int(n))<0){check();throw Failure("TLS_FAILED: provider handshake input","TLS_PROVIDER_INPUT");}}}}
        char data[8192];int n=api_.info(id_,data,sizeof(data));if(n<=0)throw Failure("TLS_FAILED: provider metadata","TLS_PROVIDER_INFO");auto info=json_parse(std::string(data,size_t(n)));alpn_=info.at("alpn").scalar();version_=info.at("version").scalar()=="772"?"TLS1.3":"TLS1.2";
    }
    Bytes encrypt(const Bytes& plain){check();for(size_t offset=0;offset<plain.size();offset+=16384){auto n=std::min(size_t(16384),plain.size()-offset);if(api_.write(id_,reinterpret_cast<char*>(const_cast<uint8_t*>(plain.data()+offset)),int(n))!=int(n)){check();throw Failure("TLS_FAILED: provider encryption","TLS_PROVIDER_ENCRYPT");}}return drain(0);}
    Bytes feed(const uint8_t* data,size_t n){
        if(n){if(input_.size()+n>262144)throw Failure("TLS_FAILED: provider input buffer limit","TLS_PROVIDER_LIMIT");input_.insert(input_.end(),data,data+n);}
        auto out=drain(1);check();if(recordwise_&&(!out.empty()||!api_.ready_input(id_)))return out;
        if(!input_.empty()){
            size_t count=std::min(input_.size(),size_t(65536));
            if(recordwise_){if(input_.size()<5)return out;count=size_t(input_[3])*256+input_[4]+5;if(count>18437||input_[0]<20||input_[0]>23||input_[1]!=3)throw Failure("TLS_FAILED: TLS record framing","TLS_RECORD_FRAMING");if(input_.size()<count)return out;}
            if(api_.feed(id_,reinterpret_cast<char*>(input_.data()),int(count))<0){check();throw Failure("TLS_FAILED: provider input","TLS_PROVIDER_INPUT");}
            input_.erase(input_.begin(),input_.begin()+std::ptrdiff_t(count));auto plain=drain(1);out.insert(out.end(),plain.begin(),plain.end());
        }
        check();return out;
    }
    Bytes release_input(){if(!recordwise_||!api_.ready_input(id_))throw Failure("PROTOCOL_FAILED: TLS record boundary required for Vision","VISION_TLS_BOUNDARY");return std::exchange(input_,{});}
    Bytes take_control(){return drain(0);}
    bool closed()const{return api_.state(id_)==2;}
    bool negotiating()const{return api_.state(id_)==0;}
    size_t pending_bytes()const{return input_.size()+size_t(!api_.ready_input(id_));}
    Bytes close_notify(){if(api_.shutdown(id_)<0){check();throw Failure("TLS_FAILED: provider shutdown","TLS_PROVIDER_SHUTDOWN");}return drain(0);}
    const std::string& selected_alpn()const{return alpn_;}
    const std::string& version()const{return version_;}
};
}
