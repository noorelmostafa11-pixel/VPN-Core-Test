#pragma once
#include "tls.hpp"
#include "http2.hpp"
#include "muxcool.hpp"
#include "simple-obfs.hpp"

namespace vpn {
class SecureStream {
    Tls tls_;bool secure_=false,direct_receive_=false;Bytes initial_;
public:
    void handshake(Socket& s,const Config& c,Clock::time_point d){secure_=c.security=="tls"||c.security=="reality"||c.security=="xtls";if(secure_){tls_.handshake(s,c,d);initial_=tls_.feed(nullptr,0);for(;;){auto control=tls_.take_control();send_all(s,control.data(),control.size(),d);if(!tls_.negotiating())break;auto b=receive_some(s,d);auto plain=tls_.feed(b.data(),b.size());initial_.insert(initial_.end(),plain.begin(),plain.end());}}}
    Bytes encrypt(const Bytes& b){return secure_?tls_.encrypt(b):b;}
    Bytes feed(const uint8_t* b,size_t n){auto out=std::exchange(initial_,{});auto data=secure_&&!direct_receive_?tls_.feed(b,n):n?Bytes(b,b+n):Bytes{};out.insert(out.end(),data.begin(),data.end());return out;}
    Bytes switch_direct_receive(){if(direct_receive_)throw Failure("PROTOCOL_FAILED: duplicate Vision direct transition","VISION_DIRECT_STATE");auto out=tls_.release_input();direct_receive_=true;return out;}
    bool direct_receive()const{return direct_receive_;}
    Bytes take_control(){return secure_?tls_.take_control():Bytes{};}
    bool negotiating()const{return secure_&&tls_.negotiating();}
    size_t pending_bytes()const{return secure_&&!direct_receive_?tls_.pending_bytes():0;}
    Bytes close_notify(){return secure_&&!direct_receive_?tls_.close_notify():Bytes{};}
    bool closed()const{return secure_&&tls_.closed();}
    bool secure()const{return secure_;}
    const std::string& alpn()const{return tls_.selected_alpn();}
    const std::string& version()const{return tls_.version();}
};
inline void send_secure(Socket& socket,SecureStream& tls,const Bytes& plain,Clock::time_point deadline){auto wire=tls.encrypt(plain);auto control=tls.take_control();send_all(socket,control.data(),control.size(),deadline);send_all(socket,wire.data(),wire.size(),deadline);}
class Transport {
    const Config& c_;SimpleObfs obfs_;Http2 h2_;HttpBody body_;MuxCool mux_;Bytes input_,control_;bool closed_=false,fragment_=false,xhttp_h2_=false;std::string websocket_key_,early_value_;
    bool use_h2()const{return c_.transport=="grpc"||xhttp_h2_;}
    Bytes ws_frame(uint8_t opcode,const Bytes& data){Bytes b{uint8_t(0x80|opcode)};if(data.size()<126)b.push_back(uint8_t(0x80|data.size()));else if(data.size()<=65535){b.push_back(0xfe);be16(b,data.size());}else{b.push_back(0xff);for(int i=7;i>=0;--i)b.push_back(uint8_t(uint64_t(data.size())>>(8*i)));}auto mask=random_bytes(4);append(b,mask);for(size_t i=0;i<data.size();++i)b.push_back(data[i]^mask[i%4]);return b;}
public:
    explicit Transport(const Config& c):c_(c),obfs_(c),body_(c.transport=="raw"),mux_(c){}
    Bytes open(Socket& server,SecureStream& tls,Clock::time_point deadline,Bytes* early=nullptr){if(c_.transport=="obfs-http"||c_.transport=="obfs-tls")return tls.feed(nullptr,0);if(c_.transport=="raw"){if(lower(c_.header_type)=="http"){auto request=to_bytes("GET "+http_path(c_)+" HTTP/1.1\r\nHost: "+http_host(c_)+"\r\nConnection: keep-alive\r\n\r\n");send_secure(server,tls,request,deadline);}return tls.feed(nullptr,0);}
        if(c_.transport=="xhttp"){(void)xhttp_options(c_);xhttp_h2_=tls.secure()&&tls.alpn()=="h2";if(xhttp_h2_){send_secure(server,tls,h2_.open(c_),deadline);return tls.feed(nullptr,0);}if(tls.secure()&&!tls.alpn().empty()&&tls.alpn()!="http/1.1")throw Failure("TRANSPORT_FAILED: XHTTP requires HTTP/1.1 or h2 ALPN","ALPN_XHTTP");std::string request="POST "+http_path(c_,true)+" HTTP/1.1\r\nHost: "+http_host(c_)+"\r\nTransfer-Encoding: chunked\r\n";for(const auto& p:xhttp_headers(c_))request+=p.first+": "+p.second+"\r\n";request+="\r\n";send_secure(server,tls,to_bytes(request),deadline);return tls.feed(nullptr,0);}
        if(c_.transport=="grpc"){if(tls.secure()&&tls.alpn()!="h2")throw std::runtime_error("TRANSPORT_FAILED: gRPC requires h2 ALPN");send_secure(server,tls,h2_.open(c_),deadline);return tls.feed(nullptr,0);}
        if(tls.secure()&&!tls.alpn().empty()&&tls.alpn()!="http/1.1")throw Failure("TRANSPORT_FAILED: upgrade requires HTTP/1.1 ALPN","ALPN_CARRIER_INCOMPATIBLE");auto path=http_path(c_);auto host=http_host(c_);
        std::string request="GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n";if(c_.transport=="websocket"){websocket_key_=b64_encode(random_bytes(16));request+="Sec-WebSocket-Key: "+websocket_key_+"\r\nSec-WebSocket-Version: 13\r\n";if(early&&c_.ws_early_data&&!early->empty()){auto name=lower(c_.ws_early_header);check_http_name(name);if(std::set<std::string>{"host","connection","upgrade","sec-websocket-key","sec-websocket-version","sec-websocket-accept","sec-websocket-extensions","content-length","transfer-encoding"}.count(name))throw Failure("PARSE_INVALID: reserved early data header","WEBSOCKET_EARLY_HEADER");size_t n=std::min(size_t(c_.ws_early_data),early->size());early_value_=b64_encode(Bytes(early->begin(),early->begin()+std::ptrdiff_t(n)));while(!early_value_.empty()&&early_value_.back()=='=')early_value_.pop_back();std::replace(early_value_.begin(),early_value_.end(),'+','-');std::replace(early_value_.begin(),early_value_.end(),'/','_');request+=c_.ws_early_header+": "+early_value_+"\r\n";consume(*early,n);}}request+="\r\n";send_secure(server,tls,to_bytes(request),deadline);Bytes data=tls.feed(nullptr,0);
        for(;;){auto text=from_bytes(data);auto end=text.find("\r\n\r\n");if(end!=std::string::npos){auto status=http_status(text.substr(0,text.find("\r\n")));if(status!=101)throw Failure("TRANSPORT_FAILED: upgrade status is not 101","HTTP_UPGRADE_STATUS",0,status);auto headers=http_headers(text.substr(0,end));std::istringstream tokens(lower(option(headers,{"connection"})));std::string token;bool upgrade=false;while(std::getline(tokens,token,','))if(trim(token)=="upgrade")upgrade=true;if(lower(option(headers,{"upgrade"}))!="websocket"||!upgrade)throw Failure("TRANSPORT_FAILED: invalid upgrade response","HTTP_UPGRADE_HEADERS");if(c_.transport=="websocket"){auto accept=b64_encode(digest("sha1",to_bytes(websocket_key_+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));if(option(headers,{"sec-websocket-accept"})!=accept)throw Failure("TRANSPORT_FAILED: WebSocket accept mismatch","WEBSOCKET_ACCEPT");if(headers.count("sec-websocket-extensions"))throw Failure("TRANSPORT_FAILED: unsolicited WebSocket extension","WEBSOCKET_EXTENSION");if(headers.count("sec-websocket-protocol")&&(lower(c_.ws_early_header)!="sec-websocket-protocol"||early_value_.empty()||headers.at("sec-websocket-protocol")!=early_value_))throw Failure("TRANSPORT_FAILED: unexpected WebSocket protocol","WEBSOCKET_PROTOCOL");}return Bytes(data.begin()+std::ptrdiff_t(end+4),data.end());}
            if(data.size()>65536)throw std::runtime_error("TRANSPORT_FAILED: upgrade header limit");auto incoming=receive_some(server,deadline);append(data,tls.feed(incoming.data(),incoming.size()));auto token=tls.take_control();send_all(server,token.data(),token.size(),deadline);}
    }
    Bytes prepare(const Bytes& b){return c_.ss_plugin_mux?mux_.encode(b):b;}
    Bytes encode_prepared(const Bytes& b){if(c_.transport=="obfs-http"||c_.transport=="obfs-tls")return obfs_.encode(b);if(use_h2())return h2_.encode(b);if(c_.transport=="xhttp"){if(b.empty())return {};std::ostringstream n;n<<std::hex<<b.size();Bytes out=to_bytes(n.str()+"\r\n");append(out,b);append(out,Bytes{13,10});return out;}return c_.transport=="websocket"?ws_frame(2,b):b;}
    Bytes encode(const Bytes& b){return encode_prepared(prepare(b));}
    Bytes finish(){if(c_.ss_plugin_mux)return ws_frame(2,mux_.finish());return use_h2()?h2_.finish():c_.transport=="xhttp"?to_bytes("0\r\n\r\n"):c_.transport=="websocket"?ws_frame(8,Bytes{3,232}):Bytes{};}
    bool closed()const{return use_h2()?h2_.closed():c_.transport=="xhttp"?body_.closed():closed_||(c_.ss_plugin_mux&&mux_.closed());}
    size_t pending_bytes()const{return use_h2()?h2_.pending_bytes():0;}
    Bytes take_control(){return use_h2()?h2_.control():std::exchange(control_,{});}
    Bytes decode(const Bytes& incoming){if(c_.transport=="obfs-http"||c_.transport=="obfs-tls")return obfs_.decode(incoming);if(use_h2())return h2_.decode(incoming);if(c_.transport=="xhttp"||(c_.transport=="raw"&&lower(c_.header_type)=="http"))return body_.feed(incoming);if(c_.transport!="websocket")return incoming;append(input_,incoming);if(input_.size()>1048576)throw std::runtime_error("TRANSPORT_FAILED: WebSocket buffer limit");Bytes out;
        for(;;){if(input_.size()<2)break;bool fin=(input_[0]&128)!=0;uint8_t opcode=input_[0]&15;if((input_[0]&0x70)||(input_[1]&0x80))throw std::runtime_error("TRANSPORT_FAILED: invalid server WebSocket flags");uint64_t n=input_[1]&127;size_t header=2;if(n==126){if(input_.size()<4)break;n=get16(input_,2);header=4;if(n<126)throw std::runtime_error("TRANSPORT_FAILED: noncanonical WebSocket length");}else if(n==127){if(input_.size()<10)break;n=0;for(size_t i=2;i<10;++i)n=(n<<8)|input_[i];header=10;if(n<=65535)throw std::runtime_error("TRANSPORT_FAILED: noncanonical WebSocket length");}if(n>524288)throw std::runtime_error("TRANSPORT_FAILED: WebSocket frame limit");if(opcode>=8&&(!fin||n>125))throw std::runtime_error("TRANSPORT_FAILED: invalid WebSocket control frame");if(input_.size()<header+size_t(n))break;consume(input_,header);auto body=consume(input_,size_t(n));
            if(opcode==8){if(body.size()==1)throw std::runtime_error("TRANSPORT_FAILED: invalid WebSocket close");append(control_,ws_frame(8,body));closed_=true;if(!input_.empty())throw std::runtime_error("TRANSPORT_FAILED: data after WebSocket close");break;}
            if(opcode==9){append(control_,ws_frame(10,body));continue;}if(opcode==10)continue;if(opcode==2){if(fragment_)throw std::runtime_error("TRANSPORT_FAILED: overlapping WebSocket fragments");fragment_=!fin;}else if(opcode==0){if(!fragment_)throw std::runtime_error("TRANSPORT_FAILED: orphan WebSocket continuation");if(fin)fragment_=false;}else throw std::runtime_error("TRANSPORT_FAILED: unsupported WebSocket opcode");append(out,body);}return c_.ss_plugin_mux?mux_.decode(out):out;}
};
}
