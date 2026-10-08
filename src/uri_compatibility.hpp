#pragma once
#include "json.hpp"
#include <set>

namespace vpn {
// Import compatibility is additive. Call only after the original JSON path
// failed, and require a complete object before accepting any alternate syntax.
inline std::string extra_json_whitespace(const std::string& text) {
    std::string out;out.reserve(text.size());char quote=0;bool escaped=false;
    for(size_t i=0;i<text.size();++i){char ch=text[i];
        if(quote){out+=ch;if(escaped)escaped=false;else if(ch=='\\')escaped=true;else if(ch==quote)quote=0;}
        else if(ch=='"'||ch=='\''){quote=ch;out+=ch;}
        else if(ch=='+'){
            bool exponent=i>0&&(text[i-1]=='e'||text[i-1]=='E')&&i+1<text.size()&&text[i+1]>='0'&&text[i+1]<='9';
            out+=exponent?'+':' ';
        }else out+=ch;
    }return out;
}
inline std::string extra_json_quotes(const std::string& text) {
    std::string out;out.reserve(text.size());char quote=0;
    for(size_t i=0;i<text.size();++i){char ch=text[i];
        if(!quote){if(ch=='"'||ch=='\''){quote=ch;out+='"';}else out+=ch;continue;}
        if(ch=='\\'){
            if(i+1==text.size())return text;
            char next=text[++i];
            if(quote=='\''&&next=='\'')out+='\'';
            else{out+='\\';out+=next;}
        }else if(ch==quote){out+='"';quote=0;}
        else if(quote=='\''&&ch=='"')out+="\\\"";
        else out+=ch;
    }return quote?text:out;
}
inline Json compatible_xhttp_extra(const std::string& decoded,const std::string& twice_decoded,std::string& strategy) {
    auto object=[](const std::string& text,Json& out){try{out=json_parse(text);return out.kind==Json::Object;}catch(...){return false;}};
    Json out;auto whitespace=extra_json_whitespace(decoded);
    if(whitespace!=decoded&&object(whitespace,out)){strategy="XHTTP_EXTRA_PLUS_WHITESPACE";return out;}
    auto quotes=extra_json_quotes(whitespace);
    if(quotes!=whitespace&&object(quotes,out)){strategy=whitespace==decoded?"XHTTP_EXTRA_SINGLE_QUOTES":"XHTTP_EXTRA_QUOTES_AND_WHITESPACE";return out;}
    auto start=lower(trim(decoded));
    if(start.find("%7b")==0&&twice_decoded!=decoded&&object(twice_decoded,out)){strategy="XHTTP_EXTRA_DOUBLE_URL_ENCODING";return out;}
    return Json(decoded);
}
inline bool compatible_none_encryption(const std::string& text) {
    if(text.size()<=4)return false;auto value=lower(text.substr(0,8));
    return value.find("none=")==0||value.find("none@")==0||value.find("none\xc2\xac" "e=")==0;
}
inline bool add_reality_semicolon_aliases(std::map<std::string,std::string>& decoded,std::map<std::string,std::string>& raw) {
    static const std::set<std::string> public_keys{"pbk","password","publickey","public-key"};
    for(const auto& name:public_keys)if(decoded.count(name))return false;
    bool found=false;
    for(const auto& entry:decoded){auto name=entry.first;auto first=name.find_first_not_of(';');
        if(first!=std::string::npos&&first&&public_keys.count(name.substr(first))&&!entry.second.empty())found=true;
    }if(!found)return false;
    static const std::set<std::string> keys{"pbk","password","publickey","public-key","sid","shortid","short-id","spx","spiderx","sni","servername","server-name","peer","fp","fingerprint","client-fingerprint","alpn","flow","type","network","net","security","tls","encryption","header-type","headertype","path","wspath","host","authority","servicename","service-name","grpc-service-name","service_name","mode","extra","fm","finalmask","pqv","mldsa65verify","ech","echconfiglist","ech-config-list"};
    // Keep every original key, and add aliases without replacing canonical keys.
    auto source=decoded;
    for(const auto& entry:source){auto first=entry.first.find_first_not_of(';');
        if(first==std::string::npos||!first)continue;auto name=entry.first.substr(first);if(!keys.count(name))continue;
        decoded.emplace(name,entry.second);auto original=raw.find(entry.first);if(original!=raw.end())raw.emplace(name,original->second);
    }return true;
}
}
