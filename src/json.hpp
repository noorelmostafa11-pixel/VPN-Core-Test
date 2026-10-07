#pragma once
#include "base.hpp"

namespace vpn {
// Project-owned bounded JSON reader/writer. No third-party JSON code.
struct Json {
    enum Kind {Null,Boolean,Number,String,Array,Object} kind=Null;
    std::string text;std::vector<Json> array;std::map<std::string,Json> object;
    Json()=default;explicit Json(std::string s):kind(String),text(std::move(s)){}
    static Json boolean(bool b){Json j;j.kind=Boolean;j.text=b?"true":"false";return j;}
    static Json integer(uint64_t n){Json j;j.kind=Number;j.text=std::to_string(n);return j;}
    static Json obj(){Json j;j.kind=Object;return j;}
    static Json arr(){Json j;j.kind=Array;return j;}
    bool has(const std::string& k)const{return object.count(k)>0;}
    const Json& at(const std::string& k)const{static const Json empty;auto i=object.find(k);return i==object.end()?empty:i->second;}
    std::string scalar()const{return kind==String||kind==Number||kind==Boolean?text:"";}
    Json& operator[](const std::string& k){kind=Object;return object[k];}
};
inline std::string json_quote(const std::string& s) {
    std::string out="\"";const char* hex="0123456789abcdef";
    for(unsigned char c:s){if(c=='"'||c=='\\'){out+='\\';out+=char(c);}else if(c<32){out+="\\u00";out+=hex[c>>4];out+=hex[c&15];}else out+=char(c);}return out+'"';
}
inline std::string json_dump(const Json& j) {
    if(j.kind==Json::String)return json_quote(j.text);
    if(j.kind==Json::Number||j.kind==Json::Boolean)return j.text;
    if(j.kind==Json::Null)return "null";
    std::string s=j.kind==Json::Object?"{":"[";bool first=true;
    if(j.kind==Json::Object)for(const auto& kv:j.object){if(!first)s+=',';first=false;s+=json_quote(kv.first)+':'+json_dump(kv.second);}
    else for(const auto& v:j.array){if(!first)s+=',';first=false;s+=json_dump(v);}
    return s+(j.kind==Json::Object?"}":"]");
}
class JsonReader {
    const std::string& s_;size_t i_=0;
    [[noreturn]] void bad()const{throw std::runtime_error("PARSE_INVALID: malformed JSON");}
    void space(){while(i_<s_.size()&&(s_[i_]==' '||s_[i_]=='\r'||s_[i_]=='\n'||s_[i_]=='\t'))++i_;}
    uint32_t hex4(){uint32_t n=0;for(int k=0;k<4;++k){if(i_==s_.size()||hex_digit(s_[i_])<0)bad();n=n*16+unsigned(hex_digit(s_[i_++]));}return n;}
    static void utf8(std::string& o,uint32_t n){if(n<128)o+=char(n);else if(n<2048){o+=char(192|(n>>6));o+=char(128|(n&63));}else if(n<65536){o+=char(224|(n>>12));o+=char(128|((n>>6)&63));o+=char(128|(n&63));}else{o+=char(240|(n>>18));o+=char(128|((n>>12)&63));o+=char(128|((n>>6)&63));o+=char(128|(n&63));}}
    std::string string(){if(i_>=s_.size()||s_[i_++]!='"')bad();std::string o;
        while(i_<s_.size()){unsigned char c=s_[i_++];if(c=='"')return o;if(c<32)bad();if(c!='\\'){o+=char(c);continue;}if(i_==s_.size())bad();char e=s_[i_++];
            if(e=='"'||e=='\\'||e=='/')o+=e;else if(e=='b')o+='\b';else if(e=='f')o+='\f';else if(e=='n')o+='\n';else if(e=='r')o+='\r';else if(e=='t')o+='\t';else if(e=='u'){uint32_t n=hex4();if(n>=0xd800&&n<=0xdbff){if(i_+2>s_.size()||s_[i_]!='\\'||s_[i_+1]!='u')bad();i_+=2;auto low=hex4();if(low<0xdc00||low>0xdfff)bad();n=65536+((n-0xd800)<<10)+(low-0xdc00);}else if(n>=0xdc00&&n<=0xdfff)bad();utf8(o,n);}else bad();}bad();}
    Json value(unsigned depth){if(depth>32)bad();space();if(i_==s_.size())bad();char c=s_[i_];
        if(c=='"')return Json(string());
        if(c=='{'||c=='['){++i_;Json j=c=='{'?Json::obj():Json::arr();space();char end=c=='{'?'}':']';if(i_<s_.size()&&s_[i_]==end){++i_;return j;}
            for(;;){space();if(c=='{'){auto k=string();space();if(i_==s_.size()||s_[i_++]!=':')bad();j.object[k]=value(depth+1);}else j.array.push_back(value(depth+1));space();if(i_==s_.size())bad();char x=s_[i_++];if(x==end)return j;if(x!=',')bad();}}
        if(s_.compare(i_,4,"null")==0){i_+=4;return Json();}if(s_.compare(i_,4,"true")==0){i_+=4;return Json::boolean(true);}if(s_.compare(i_,5,"false")==0){i_+=5;return Json::boolean(false);}
        size_t start=i_;if(c=='-')++i_;if(i_==s_.size()||s_[i_]<'0'||s_[i_]>'9')bad();if(s_[i_]=='0')++i_;else while(i_<s_.size()&&s_[i_]>='0'&&s_[i_]<='9')++i_;
        if(i_<s_.size()&&s_[i_]=='.'){++i_;size_t p=i_;while(i_<s_.size()&&s_[i_]>='0'&&s_[i_]<='9')++i_;if(i_==p)bad();}
        if(i_<s_.size()&&(s_[i_]=='e'||s_[i_]=='E')){++i_;if(i_<s_.size()&&(s_[i_]=='+'||s_[i_]=='-'))++i_;size_t p=i_;while(i_<s_.size()&&s_[i_]>='0'&&s_[i_]<'9'+1)++i_;if(i_==p)bad();}
        Json j;j.kind=Json::Number;j.text=s_.substr(start,i_-start);return j;}
public:explicit JsonReader(const std::string& s):s_(s){}Json parse(){if(s_.size()>1048576)bad();auto j=value(0);space();if(i_!=s_.size())bad();return j;}
};
inline Json json_parse(const std::string& s){return JsonReader(s).parse();}
}
