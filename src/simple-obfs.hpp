#pragma once
#include "protocol.hpp"

namespace vpn {
// SIP003 simple-obfs is a wire disguise, independently framed from real TLS.
class SimpleObfs {
    const Config& c_;bool sent_=false,http_header_=false;unsigned tls_stage_=0;Bytes input_;
    static Bytes record(uint8_t type,const Bytes& data){if(data.size()>65535)throw Failure("TRANSPORT_FAILED: obfs record size","OBFS_RECORD_SIZE");Bytes out{type,3,3};be16(out,data.size());append(out,data);return out;}
    Bytes hello(const Bytes& data){
        auto host=c_.host_header.empty()?c_.server:c_.host_header;check_http_value(host);if(host.size()>255)throw Failure("PARSE_INVALID: obfs host length","OBFS_HOST");
        Bytes body{3,3};be32(body,uint32_t(std::time(nullptr)));append(body,random_bytes(28));body.push_back(32);append(body,random_bytes(32));
        // A normal TLS cipher list; encrypted SS bytes travel in session_ticket.
        Bytes suites{0xc0,0x2c,0xc0,0x30,0,0x9f,0xcc,0xa9,0xcc,0xa8,0xcc,0xaa,0xc0,0x2b,0xc0,0x2f,0,0x9e,0xc0,0x24,0xc0,0x28,0,0x6b,0xc0,0x23,0xc0,0x27,0,0x67,0xc0,0x0a,0xc0,0x14,0,0x39,0xc0,9,0xc0,0x13,0,0x33,0,0x9d,0,0x9c,0,0x3d,0,0x3c,0,0x35,0,0x2f,0,0xff};
        be16(body,suites.size());append(body,suites);append(body,Bytes{1,0});
        Bytes extensions;be16(extensions,0x23);be16(extensions,data.size());append(extensions,data);
        be16(extensions,0);be16(extensions,host.size()+5);be16(extensions,host.size()+3);extensions.push_back(0);be16(extensions,host.size());append(extensions,to_bytes(host));
        // These extensions match a TLS 1.2-looking hello; no authentication is implied.
        append(extensions,Bytes{0,0xb,0,4,3,1,0,2,0,0xa,0,0xa,0,8,0,0x1d,0,0x17,0,0x19,0,0x18,0,0xd,0,0x20,0,0x1e,6,1,6,2,6,3,5,1,5,2,5,3,4,1,4,2,4,3,3,1,3,2,3,3,2,1,2,2,2,3,0,0x16,0,0,0,0x17,0,0});
        be16(body,extensions.size());append(body,extensions);Bytes handshake{1,uint8_t(body.size()>>16),uint8_t(body.size()>>8),uint8_t(body.size())};append(handshake,body);auto out=record(22,handshake);out[2]=1;return out;
    }
public:
    explicit SimpleObfs(const Config& c):c_(c){}
    Bytes encode(const Bytes& data){
        if(data.empty())return {};
        if(!sent_){sent_=true;if(c_.transport=="obfs-http"){auto host=c_.host_header.empty()?c_.server:c_.host_header;check_http_value(host);auto method=option(c_.ss_plugin_options,{"obfs-http-method"},"GET");check_http_name(method);Bytes out=to_bytes(method+" "+http_path(c_)+" HTTP/1.1\r\nHost: "+host+"\r\nUser-Agent: curl/7.52.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "+b64_encode(random_bytes(16))+"\r\nContent-Length: "+std::to_string(data.size())+"\r\n\r\n");append(out,data);return out;}return hello(data);}
        if(c_.transport=="obfs-http")return data;
        Bytes out;for(size_t i=0;i<data.size();i+=16384){auto n=std::min(size_t(16384),data.size()-i);append(out,record(23,Bytes(data.begin()+std::ptrdiff_t(i),data.begin()+std::ptrdiff_t(i+n))));}return out;
    }
    Bytes decode(const Bytes& data){
        append(input_,data);if(input_.size()>1048576)throw Failure("TRANSPORT_FAILED: obfs input limit","OBFS_INPUT_LIMIT");
        if(c_.transport=="obfs-http"){
            if(!http_header_){auto text=from_bytes(input_);auto end=text.find("\r\n\r\n");if(end==std::string::npos){if(input_.size()>65536)throw Failure("TRANSPORT_FAILED: obfs HTTP header limit","OBFS_HTTP_HEADER");return {};}auto status=http_status(text.substr(0,text.find("\r\n")));if(status!=101)throw Failure("TRANSPORT_FAILED: obfs HTTP status","OBFS_HTTP_STATUS",0,status);(void)http_headers(text.substr(0,end));consume(input_,end+4);http_header_=true;}
            return consume(input_,input_.size());
        }
        Bytes out;
        while(input_.size()>=5){auto type=input_[0];if(input_[1]!=3||(input_[2]!=1&&input_[2]!=3))throw Failure("TRANSPORT_FAILED: obfs TLS version","OBFS_TLS_HEADER");auto n=get16(input_,3);if(input_.size()<n+5)break;consume(input_,5);auto body=consume(input_,n);
            if(tls_stage_==0){if(type!=22||body.size()<4||body[0]!=2)throw Failure("TRANSPORT_FAILED: obfs ServerHello","OBFS_TLS_SERVER_HELLO");tls_stage_=1;}
            else if(tls_stage_==1){if(type!=20||body!=Bytes{1})throw Failure("TRANSPORT_FAILED: obfs ChangeCipherSpec","OBFS_TLS_CCS");tls_stage_=2;}
            else if(tls_stage_==2){if(type!=22)throw Failure("TRANSPORT_FAILED: obfs encrypted handshake","OBFS_TLS_HANDSHAKE");append(out,body);tls_stage_=3;}
            else {if(type!=23)throw Failure("TRANSPORT_FAILED: obfs application record","OBFS_TLS_RECORD");append(out,body);}
        }
        return out;
    }
};
}
