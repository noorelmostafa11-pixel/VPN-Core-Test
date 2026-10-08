#include "../src/transport.hpp"
#include "../src/xhttp-provider.hpp"
#include <iostream>
// Synthetic fixtures only. Production inspection never prints source options.
int main(){std::string line;while(std::getline(std::cin,line)){try{
    auto request=vpn::json_parse(line);auto uri=request.at("uri").scalar();vpn::Config c;vpn::parse_uri(c,uri);
    auto out=vpn::inspection(c);out["source_uri_preserved"]=vpn::Json::boolean(c.original_uri==uri);
    out["original_options"]=vpn::Json::obj();for(const auto& entry:c.original_options)out["original_options"][entry.first]=vpn::Json(entry.second);
    out["resolved_extra"]=c.extra;out["resolved_public_key"]=vpn::Json(c.public_key);out["resolved_short_id"]=vpn::Json(c.short_id);
    out["provider_extra"]=vpn::active_http_provider_settings(c).at("extra");
    out["resolved_server_name"]=vpn::Json(c.tls_name);std::cout<<vpn::json_dump(out)<<'\n';
}catch(const std::exception& e){vpn::Json out=vpn::Json::obj();auto f=dynamic_cast<const vpn::Failure*>(&e);out["reason_code"]=vpn::Json(f?f->code:"CONFIG_VALIDATION_INVALID");out["error"]=vpn::Json(e.what());std::cout<<vpn::json_dump(out)<<'\n';}}}
