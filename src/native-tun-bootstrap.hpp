// Additive Native TUN policy metadata; existing Config/parser is unchanged.
#pragma once
#include "config.hpp"
namespace vpn {
struct NativeBootstrapTarget {std::string host;uint16_t port;};
inline const Json& bootstrap_field(const Json& j,const std::string& name) {
    // The provider receives json_dump(Config.extra), in sorted key order.
    // Go's case-insensitive struct decoding overwrites earlier matching keys.
    static const Json empty;const Json* result=&empty;
    for(const auto& kv:j.object)if(lower(kv.first)==name)result=&kv.second;
    return *result;
}
inline void bootstrap_add(std::vector<NativeBootstrapTarget>& targets,std::string host,uint16_t port) {
    if(host.empty()||!port)throw Failure("STARTUP_FAILED: bootstrap endpoint","TUN_BOOTSTRAP_ENDPOINT");
    for(const auto& t:targets)if(t.host==host&&t.port==port)return;
    targets.push_back({std::move(host),port});
}
inline void bootstrap_ech(std::vector<NativeBootstrapTarget>& targets,std::string text) {
    auto plus=text.find('+');
    if(plus!=std::string::npos)text=text.substr(plus+1);
    else{std::istringstream fields(text);std::string first,second,third;if((fields>>first>>second)&&!(fields>>third))text=second;}
    auto scheme_end=text.find("://");if(scheme_end==std::string::npos)return; // literal ECH config, no network lookup
    auto scheme=text.substr(0,scheme_end);unsigned port=scheme=="https"?443:scheme=="tls"?853:53;
    if(scheme!="https"&&scheme!="tls"&&scheme!="tcp"&&scheme!="udp")throw Failure("STARTUP_FAILED: ECH resolver","TUN_BOOTSTRAP_ENDPOINT");
    auto authority=text.substr(scheme_end+3);authority=authority.substr(0,authority.find_first_of("/?#"));
    if(authority.empty()||authority.find('@')!=std::string::npos)throw Failure("STARTUP_FAILED: ECH authority","TUN_BOOTSTRAP_ENDPOINT");
    std::string host,port_text;
    if(authority[0]=='['){auto end=authority.find(']');if(end==std::string::npos)throw Failure("STARTUP_FAILED: ECH IPv6","TUN_BOOTSTRAP_ENDPOINT");host=uri_decode(authority.substr(1,end-1));if(end+1<authority.size()){if(authority[end+1]!=':')throw Failure("STARTUP_FAILED: ECH port","TUN_BOOTSTRAP_ENDPOINT");port_text=authority.substr(end+2);}}
    else{auto colon=authority.find(':');host=authority.substr(0,colon);if(colon!=std::string::npos)port_text=authority.substr(colon+1);}
    if(!port_text.empty())port=number(port_text,1,65535);
    bootstrap_add(targets,std::move(host),uint16_t(port));
}
inline std::vector<NativeBootstrapTarget> native_bootstrap_targets(const Config& c) {
    std::vector<NativeBootstrapTarget> targets;bootstrap_add(targets,c.server,c.port);
    if(c.security=="tls"||c.security=="xtls")bootstrap_ech(targets,c.ech);
    if(c.transport=="xhttp"||c.transport=="http"){
        const auto& download=bootstrap_field(c.extra,"downloadsettings");
        if(download.kind==Json::Object){
            auto address=bootstrap_field(download,"address").scalar();auto port=bootstrap_field(download,"port").scalar();
            bootstrap_add(targets,address.empty()?c.server:address,port.empty()||port=="0"?c.port:uint16_t(number(port,1,65535)));
            auto security=bootstrap_field(download,"security").scalar();if(security.empty())security=c.security;
            if(security=="tls"){
                auto ech=bootstrap_field(bootstrap_field(download,"tlssettings"),"echconfiglist").scalar();
                bootstrap_ech(targets,ech.empty()?c.ech:ech);
            }
        }
    }
    return targets;
}
inline std::string native_bootstrap_json(const Config& c) {
    Json output=Json::arr();for(const auto& t:native_bootstrap_targets(c)){auto j=Json::obj();j["host"]=Json(t.host);j["port"]=Json::integer(t.port);output.array.push_back(std::move(j));}return json_dump(output);
}
}
