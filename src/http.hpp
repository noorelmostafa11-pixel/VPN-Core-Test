// Copyright (c) 2026 Vpn project owner (noorelmostafa11-pixel). See NOTICE.md.
#pragma once
#include "fragment.hpp"
namespace vpn {
inline void check_http_value(const std::string& s){for(unsigned char c:s)if(c<32||c==127)throw std::runtime_error("PARSE_INVALID: invalid HTTP field");}
inline void check_http_name(const std::string& s){if(s.empty())throw std::runtime_error("PARSE_INVALID: empty HTTP field name");for(unsigned char c:s)if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||std::string("!#$%&'*+-.^_`|~").find(char(c))!=std::string::npos))throw std::runtime_error("PARSE_INVALID: invalid HTTP field name");}
inline std::string http_path(const Config& c,bool trailing=false){auto value=c.path.empty()?"/":c.path;if(value[0]!='/')value='/'+value;check_http_value(value);std::string path;const char* digits="0123456789ABCDEF";for(size_t i=0;i<value.size();++i){auto ch=uint8_t(value[i]);if(ch=='%'&&i+2<value.size()&&hex_digit(value[i+1])>=0&&hex_digit(value[i+2])>=0){path.append(value,i,3);i+=2;}else if((ch>='a'&&ch<='z')||(ch>='A'&&ch<='Z')||(ch>='0'&&ch<='9')||std::string("-._~!$&'()*+,;=:@/?").find(char(ch))!=std::string::npos)path+=char(ch);else{path+='%';path+=digits[ch>>4];path+=digits[ch&15];}}if(trailing){auto q=path.find('?');auto n=q==std::string::npos?path.size():q;if(!n||path[n-1]!='/')path.insert(n,1,'/');}return path;}
inline std::string http_host(const Config& c){auto host=c.host_header.empty()?c.server:c.host_header;
    // Upgrade virtual hosts follow explicit Host, then TLS server name, then
    // endpoint host. A Host value does not inherit the dial port. Preserve the
    // original endpoint-authority behavior for every other carrier.
    bool upgrade=(c.transport=="websocket"||c.transport=="httpupgrade");
    if(c.host_header.empty()&&upgrade){if((c.security=="tls"||c.security=="xtls")&&!c.tls_name.empty())host=c.tls_name;if(host.find(':')!=std::string::npos)host='['+host+']';}
    else if(c.host_header.empty()){if(host.find(':')!=std::string::npos)host='['+host+']';if(c.port!=(c.security=="tls"?443:80))host+=':'+std::to_string(c.port);}
    check_http_value(host);if(host.find(' ')!=std::string::npos)throw std::runtime_error("PARSE_INVALID: invalid HTTP authority");return host;}
inline unsigned http_status(const std::string& line){if(line.size()<12||(line.substr(0,9)!="HTTP/1.1 "&&line.substr(0,9)!="HTTP/1.0 ")||line[9]<'1'||line[9]>'5'||line[10]<'0'||line[10]>'9'||line[11]<'0'||line[11]>'9'||(line.size()>12&&line[12]!=' '&&line[12]!='\r'))throw Failure("TRANSPORT_FAILED: malformed HTTP status","HTTP_STATUS_INVALID");return unsigned(line[9]-'0')*100+unsigned(line[10]-'0')*10+unsigned(line[11]-'0');}
struct HttpHeaders:Options {std::vector<std::string> set_cookies;std::vector<std::pair<std::string,std::string>> fields;};
inline HttpHeaders http_headers(const std::string& text){HttpHeaders headers;std::istringstream lines(text);std::string line;std::getline(lines,line);const std::set<std::string> lists{"accept","accept-encoding","accept-language","allow","cache-control","connection","content-language","link","pragma","trailer","vary","via","warning","www-authenticate","proxy-authenticate"};while(std::getline(lines,line)){auto colon=line.find(':');if(colon==std::string::npos)throw Failure("TRANSPORT_FAILED: malformed HTTP header","HTTP_HEADER_INVALID");auto key=lower(line.substr(0,colon));try{check_http_name(key);}catch(...){throw Failure("TRANSPORT_FAILED: malformed HTTP header name","HTTP_HEADER_INVALID");}auto value=trim(line.substr(colon+1));for(unsigned char ch:value)if((ch<32&&ch!=9)||ch==127)throw Failure("TRANSPORT_FAILED: malformed HTTP header value","HTTP_HEADER_INVALID");headers.fields.emplace_back(key,value);if(key=="set-cookie"){headers.set_cookies.push_back(value);headers.emplace(key,value);continue;}auto inserted=headers.emplace(key,value);if(!inserted.second){if(lists.count(key)){inserted.first->second+=", "+value;}else if(std::set<std::string>{"host","content-length","transfer-encoding","sec-websocket-accept","sec-websocket-protocol","sec-websocket-extensions","upgrade","server","content-type","content-encoding"}.count(key)){throw Failure("TRANSPORT_FAILED: duplicate critical or non-list HTTP header","HTTP_HEADER_DUPLICATE",0,0,key);}/* Opaque fields are preserved in fields and never interpreted or combined. */}}return headers;}
inline void validate_http_carrier(const Config& c){bool http=c.transport=="obfs-http"||c.transport=="websocket"||c.transport=="httpupgrade"||c.transport=="xhttp"||c.transport=="http"||(c.transport=="raw"&&lower(c.header_type)=="http");if(http){try{(void)http_path(c);}catch(...){throw Failure("PARSE_INVALID: invalid HTTP path","HTTP_PATH_INVALID");}try{(void)http_host(c);}catch(...){throw Failure("PARSE_INVALID: invalid HTTP authority","HTTP_HOST_INVALID");}}}

struct XHttpOptions {
    bool no_grpc_header=false;MaskRange padding{100,1000};Options headers;
};
inline XHttpOptions xhttp_options(const Config& c){XHttpOptions out;if(c.mode!="stream-one")throw std::runtime_error("FEATURE_UNIMPLEMENTED: XHTTP mode");if(c.extra.kind==Json::Null)return out;if(c.extra.kind!=Json::Object)throw std::runtime_error("PARSE_INVALID: XHTTP extra must be an object");
    for(const auto& p:c.extra.object){if(p.first=="noGRPCHeader"){if(p.second.kind!=Json::Boolean)throw std::runtime_error("PARSE_INVALID: XHTTP boolean");out.no_grpc_header=p.second.text=="true";}
        else if(p.first=="xPaddingBytes")out.padding=mask_range(p.second,8192);
        else if(p.first=="headers"){if(p.second.kind!=Json::Object)throw std::runtime_error("PARSE_INVALID: XHTTP headers");for(const auto& h:p.second.object){check_http_name(h.first);auto key=lower(h.first);if(h.second.kind!=Json::String)throw std::runtime_error("PARSE_INVALID: XHTTP header value");check_http_value(h.second.text);if(key=="host"||key=="connection"||key=="transfer-encoding"||key=="content-length"||key=="upgrade"||key=="te")throw std::runtime_error("FEATURE_UNIMPLEMENTED: reserved XHTTP header");out.headers[key]=h.second.text;}}
        else if(p.first=="xmux"){if(p.second.kind!=Json::Object)throw std::runtime_error("PARSE_INVALID: XHTTP xmux");const std::set<std::string> keys{"maxConnections","maxConcurrency","cMaxReuseTimes","hMaxRequestTimes","hMaxReusableSecs","hKeepAlivePeriod"};for(const auto& x:p.second.object)if(!keys.count(x.first))throw std::runtime_error("FEATURE_UNIMPLEMENTED: XHTTP xmux option");/* one connection per SOCKS tunnel; no pooling */}
        else if(p.first=="noSSEHeader"){if(p.second.kind!=Json::Boolean)throw std::runtime_error("PARSE_INVALID: XHTTP boolean");/* response-side server setting */}
        else if(p.first=="mode"){if(p.second.scalar()!=c.mode)throw std::runtime_error("PARSE_INVALID: conflicting XHTTP mode");}
        else throw std::runtime_error("FEATURE_UNIMPLEMENTED: XHTTP option");
    }return out;
}
inline void(*validate_xhttp_build)(const Config&)=nullptr;
inline bool supported_xhttp(const Config& c){
    if(!std::set<std::string>{"","auto","packet-up","stream-up","stream-one"}.count(c.mode))throw Failure("PARSE_INVALID: unregistered XHTTP mode","XHTTP_MODE_INVALID");
    if(c.extra.kind!=Json::Null&&c.extra.kind!=Json::Object)throw Failure("PARSE_INVALID: XHTTP extra must be an object","XHTTP_CONFIGURATION");
    const std::set<std::string> keys{"host","path","mode","headers","xPaddingBytes","noGRPCHeader","noSSEHeader","scMaxEachPostBytes","scMinPostsIntervalMs","scMaxBufferedPosts","scMaxConcurrentPosts","scStreamUpServerSecs","xmux","downloadSettings","xPaddingObfsMode","xPaddingKey","xPaddingHeader","xPaddingPlacement","xPaddingMethod","uplinkHTTPMethod","sessionIDPlacement","sessionIDKey","sessionIDTable","sessionIDLength","sessionPlacement","sessionKey","seqPlacement","seqKey","uplinkDataPlacement","uplinkDataKey","uplinkChunkSize","serverMaxHeaderBytes","extra","AcceptEncoding","AcceptLanguage","CacheControl","Accept-Encoding","Accept-Language","Cache-Control","Pragma","enabled","concurrency","xudpConcurrency","xudpProxyUDP443"};
    for(const auto& item:c.extra.object)if(!keys.count(item.first))return false;
    if(!c.alpn.empty()&&std::find(c.alpn.begin(),c.alpn.end(),"h2")==c.alpn.end()&&std::find(c.alpn.begin(),c.alpn.end(),"http/1.1")==c.alpn.end()&&std::find(c.alpn.begin(),c.alpn.end(),"h3")==c.alpn.end()&&c.security!="reality")throw Failure("PARSE_INVALID: XHTTP ALPN requires h3, h2 or HTTP/1.1","XHTTP_ALPN_INVALID");
    if(validate_xhttp_build)validate_xhttp_build(c);
    return true;
}
inline Options xhttp_headers(const Config& c){auto x=xhttp_options(c);auto headers=x.headers;auto padding=std::string(x.padding.choose(),'X');auto path=http_path(c,true);std::string referer=(c.security=="tls"?"https://":"http://")+http_host(c)+path+(path.find('?')==std::string::npos?"?":"&")+"x_padding="+padding;headers["referer"]=referer;if(!x.no_grpc_header)headers["content-type"]="application/grpc";else headers.erase("content-type");headers["accept-encoding"]="identity";return headers;}
class HttpBody {
    Bytes input_;bool header_=false,chunked_=false,chunk_crlf_=false,trailers_=false,closed_=false,raw_=false,finite_=false;size_t remaining_=0;unsigned interim_=0;
    void discard(size_t n){input_.erase(input_.begin(),input_.begin()+std::ptrdiff_t(n));}
public:
    explicit HttpBody(bool raw=false):raw_(raw){}
    bool closed()const{return closed_;}
    Bytes feed(const Bytes& bytes){if(closed_&&!bytes.empty())throw Failure("TRANSPORT_FAILED: HTTP bytes after end","HTTP_BODY_AFTER_END");input_.insert(input_.end(),bytes.begin(),bytes.end());if(input_.size()>1048576)throw std::runtime_error("TRANSPORT_FAILED: HTTP buffer limit");Bytes out;
        if(!header_){for(;;){auto text=from_bytes(input_);auto end=text.find("\r\n\r\n");if(end==std::string::npos){if(input_.size()>65536)throw Failure("TRANSPORT_FAILED: HTTP header limit","HTTP_HEADER_LIMIT");return {};}
            auto status=http_status(text.substr(0,text.find("\r\n")));auto headers=http_headers(text.substr(0,end));discard(end+4);if(status==100||status==103){if(++interim_>8)throw Failure("TRANSPORT_FAILED: too many interim responses","HTTP_INTERIM_LIMIT");continue;}if(status!=200)throw Failure("TRANSPORT_FAILED: HTTP response status","HTTP_STATUS",0,status);header_=true;if(raw_)break;
            if(!option(headers,{"content-encoding"}).empty()&&lower(option(headers,{"content-encoding"}))!="identity")throw Failure("TRANSPORT_FAILED: HTTP content encoding","HTTP_CONTENT_ENCODING");
            auto te=lower(option(headers,{"transfer-encoding"}));if(!te.empty()&&te!="chunked")throw Failure("TRANSPORT_FAILED: HTTP transfer encoding","HTTP_TRANSFER_ENCODING");if(!te.empty()&&headers.count("content-length"))throw Failure("TRANSPORT_FAILED: ambiguous HTTP framing","HTTP_FRAMING_AMBIGUOUS");chunked_=te=="chunked";
            if(headers.count("content-length")){finite_=true;remaining_=number(headers.at("content-length"),0,999999999);if(!remaining_)closed_=true;}break;}}
        if(raw_||(!chunked_&&!finite_)){out=std::move(input_);input_.clear();return out;}
        if(finite_){auto n=std::min(input_.size(),remaining_);out.insert(out.end(),input_.begin(),input_.begin()+std::ptrdiff_t(n));discard(n);remaining_-=n;if(!remaining_)closed_=true;if(closed_&&!input_.empty())throw Failure("TRANSPORT_FAILED: HTTP bytes after content length","HTTP_BODY_AFTER_END");return out;}
        for(;;){if(trailers_){auto text=from_bytes(input_);if(text.substr(0,2)=="\r\n"){discard(2);closed_=true;}else{auto end=text.find("\r\n\r\n");if(end==std::string::npos){if(input_.size()>65536)throw Failure("TRANSPORT_FAILED: HTTP trailer limit","HTTP_HEADER_LIMIT");break;}(void)http_headers("TRAILERS\r\n"+text.substr(0,end));discard(end+4);closed_=true;}if(!input_.empty())throw Failure("TRANSPORT_FAILED: HTTP bytes after chunks","HTTP_BODY_AFTER_END");break;}
            if(remaining_){auto n=std::min(remaining_,input_.size());out.insert(out.end(),input_.begin(),input_.begin()+std::ptrdiff_t(n));discard(n);remaining_-=n;if(remaining_)break;chunk_crlf_=true;}
            if(chunk_crlf_){if(input_.size()<2)break;if(input_[0]!=13||input_[1]!=10)throw Failure("TRANSPORT_FAILED: HTTP chunk delimiter","HTTP_CHUNK_INVALID");discard(2);chunk_crlf_=false;}
            auto text=from_bytes(input_);auto end=text.find("\r\n");if(end==std::string::npos){if(input_.size()>1024)throw Failure("TRANSPORT_FAILED: HTTP chunk line limit","HTTP_CHUNK_INVALID");break;}auto length=text.substr(0,text.find(';')<end?text.find(';'):end);if(length.empty()||length.size()>8)throw Failure("TRANSPORT_FAILED: HTTP chunk length","HTTP_CHUNK_INVALID");size_t size=0;for(char c:length){auto n=hex_digit(c);if(n<0)throw Failure("TRANSPORT_FAILED: HTTP chunk length","HTTP_CHUNK_INVALID");size=size*16+unsigned(n);}if(size>16777216)throw Failure("TRANSPORT_FAILED: HTTP chunk size limit","HTTP_CHUNK_LIMIT");discard(end+2);remaining_=size;if(!size)trailers_=true;
        }return out;
    }
};
}
