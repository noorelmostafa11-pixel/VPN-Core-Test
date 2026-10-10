// Owned DNS endpoints. Queries cross the existing encrypted core TCP stream.
// No SOCKS listener, direct resolver socket, node rewrite or certificate bypass.
#pragma once
#include "packet-protocol-stream.hpp"
#include "netstack-provider.hpp"
#include <functional>
namespace vpn {
inline bool native_dns_flow(const NetstackFlow& flow) {
    if(flow.port!=53||(flow.protocol!=6&&flow.protocol!=17))return false;
    const uint8_t v4[]{198,18,0,53};
    const uint8_t v6[]{0xfd,0x71,0x56,0x50,0,0,0,0,0,0,0,0,0,0,0,0x53};
    return (flow.address_size==4&&std::equal(v4,v4+4,flow.address))||
        (flow.address_size==16&&std::equal(v6,v6+16,flow.address));
}
inline Bytes dns_failure_reply(const Bytes& query) {
    Bytes reply(12);if(query.size()>=2){reply[0]=query[0];reply[1]=query[1];}
    reply[2]=0x81;reply[3]=0x82;return reply;
}
inline size_t dns_question_end(const Bytes& query) {
    if(query.size()<12||query.size()>65535||(query[2]&0x80))throw Failure("DNS_FAILED: invalid request","DNS_REQUEST_INVALID");
    size_t position=12;unsigned questions=get16(query,4);
    if(questions>128)throw Failure("DNS_FAILED: question limit","DNS_REQUEST_INVALID");
    for(unsigned i=0;i<questions;++i){
        unsigned labels=0;
        for(;;){
            if(position>=query.size()||++labels>128)throw Failure("DNS_FAILED: question name","DNS_REQUEST_INVALID");
            unsigned length=query[position++];if(!length)break;
            if((length&0xc0)==0xc0){if(position>=query.size()||((size_t(length&63)<<8)|query[position])>=query.size())throw Failure("DNS_FAILED: question pointer","DNS_REQUEST_INVALID");++position;break;}
            if(length>63||length>query.size()-position)throw Failure("DNS_FAILED: question name","DNS_REQUEST_INVALID");position+=length;
        }
        if(query.size()-position<4)throw Failure("DNS_FAILED: question fields","DNS_REQUEST_INVALID");position+=4;
    }
    return position;
}
inline Bytes dns_udp_answer(const Bytes& query,Bytes answer) {
    // A 512-byte response is safe without interpreting arbitrary EDNS options.
    // Large answers explicitly request TCP retry at the SAME owned endpoint.
    if(answer.size()<=512)return answer;
    auto end=dns_question_end(query);answer.resize(end<=512?end:12);
    if(end<=512)std::copy(query.begin()+12,query.begin()+std::ptrdiff_t(end),answer.begin()+12);else answer[4]=answer[5]=0;
    answer[2]|=2;for(size_t i=6;i<12;++i)answer[i]=0;return answer;
}
class NativeDohExchange {
    TlsProviderAPI& api_=TlsProviderAPI::instance();
    uint64_t id_=0;
    Bytes wire_,plain_;
    void check(){auto state=api_.state(id_);if(state<0)throw Failure("DNS_FAILED: authenticated resolver TLS",tls_provider_reason(-state),uint32_t(-state));}
    Bytes read(int kind){Bytes result;char buffer[16384];for(;;){int n=api_.read(id_,kind,buffer,sizeof(buffer));if(n<0)throw Failure("DNS_FAILED: resolver TLS read","DNS_TLS_READ");if(!n)break;if(result.size()+size_t(n)>131072)throw Failure("DNS_FAILED: resolver buffer","DNS_BUFFER_LIMIT");result.insert(result.end(),reinterpret_cast<uint8_t*>(buffer),reinterpret_cast<uint8_t*>(buffer)+n);}return result;}
    void pump(PacketProtocolStream& stream,Clock::time_point deadline) {
        check_cancelled();if(Clock::now()>=deadline)throw Failure("DNS_FAILED: resolver deadline","DNS_UPSTREAM_TIMEOUT");
        append(wire_,read(0));if(wire_.size()>131072)throw Failure("DNS_FAILED: resolver upload limit","DNS_BUFFER_LIMIT");if(!wire_.empty()&&stream.write(wire_))wire_.clear();stream.poll();
        const auto& incoming=stream.received();if(!incoming.empty()){
            size_t n=std::min(incoming.size(),size_t(65536));
            if(api_.feed(id_,reinterpret_cast<char*>(const_cast<uint8_t*>(incoming.data())),int(n))<0){check();throw Failure("DNS_FAILED: resolver TLS input","DNS_TLS_INPUT");}
            stream.consume(n);
        }
        append(plain_,read(1));if(plain_.size()>131072)throw Failure("DNS_FAILED: resolver body limit","DNS_BUFFER_LIMIT");check();
    }
public:
    ~NativeDohExchange(){if(id_)api_.free(id_);}
    Bytes query(const Config& node,const Bytes& request,const char** phase) {
        if(phase)*phase="PROTOCOL";dns_question_end(request);auto deadline=Clock::now()+std::chrono::milliseconds(node.connect_ms);
        const std::string name="cloudflare-dns.com";Bytes destination{3,uint8_t(name.size())};append(destination,to_bytes(name));be16(destination,443);
        PacketProtocolStream stream(node,destination,phase);
        Config resolver;resolver.security="tls";resolver.tls_name=name;resolver.fingerprint="native";resolver.alpn={"http/1.1"};resolver.connect_ms=node.connect_ms;
        auto settings=json_dump(provider_settings(resolver));if(phase)*phase="TLS";
        id_=api_.create(settings.data(),int(settings.size()));if(!id_)throw Failure("DNS_FAILED: resolver TLS allocation","DNS_TLS_CREATE");
        while(api_.state(id_)!=1){pump(stream,deadline);if(api_.state(id_)==2)throw Failure("DNS_FAILED: resolver handshake closed","DNS_TLS_CLOSED");std::this_thread::sleep_for(std::chrono::milliseconds(1));}
        Bytes question=request;question[0]=question[1]=0;
        auto headers=to_bytes("POST /dns-query HTTP/1.1\r\nHost: "+name+"\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: "+std::to_string(question.size())+"\r\n\r\n");append(headers,question);
        for(size_t offset=0;offset<headers.size();offset+=16384){auto n=std::min(size_t(16384),headers.size()-offset);if(api_.write(id_,reinterpret_cast<char*>(headers.data()+offset),int(n))!=int(n)){check();throw Failure("DNS_FAILED: resolver request write","DNS_TLS_WRITE");}}
        if(phase)*phase="TRANSPORT";HttpBody body;Bytes answer,header;bool checked_type=false;
        while(!body.closed()){
            pump(stream,deadline);
            if(!plain_.empty()){
                if(!checked_type){append(header,plain_);auto text=from_bytes(header);auto end=text.find("\r\n\r\n");if(end==std::string::npos){if(header.size()>65536)throw Failure("DNS_FAILED: resolver headers","DNS_HTTP_HEADERS");}
                    else{auto fields=http_headers(text.substr(0,end));auto type=lower(option(fields,{"content-type"}));if(type!="application/dns-message")throw Failure("DNS_FAILED: resolver content type","DNS_HTTP_CONTENT_TYPE");checked_type=true;header.clear();}}
                append(answer,body.feed(std::exchange(plain_,{})));if(answer.size()>65535)throw Failure("DNS_FAILED: resolver answer limit","DNS_BUFFER_LIMIT");
            }
            if(api_.state(id_)==2&&!body.closed())throw Failure("DNS_FAILED: incomplete resolver response","DNS_HTTP_TRUNCATED");
            if(!body.closed())std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        if(answer.size()<12||get16(answer)!=0||!(answer[2]&0x80)||get16(answer,4)!=get16(request,4))throw Failure("DNS_FAILED: resolver message validation","DNS_RESPONSE_INVALID");
        answer[0]=request[0];answer[1]=request[1];if(phase)*phase="RELAY";return answer;
    }
};
class NativeDnsSession {
    const Config& node_;bool udp_,input_eof_=false,message_=false;Bytes input_,output_;
    const char** phase_;
    std::function<void(const std::exception&)> failure_;
public:
    NativeDnsSession(const Config& node,bool udp,const char** phase,std::function<void(const std::exception&)> failure):node_(node),udp_(udp),phase_(phase),failure_(std::move(failure)){}
    bool write(const Bytes& bytes){if(input_.size()+output_.size()+bytes.size()>524288)return false;append(input_,bytes);message_=true;return true;}
    void finish_upload(){input_eof_=true;}
    const Bytes& received()const noexcept{return output_;}
    void consume(size_t n){if(n>output_.size())throw Failure("DNS_FAILED: response accounting","DNS_BUFFER_LIMIT");output_.erase(output_.begin(),output_.begin()+std::ptrdiff_t(n));}
    Bytes datagram(){return std::exchange(output_,{});}
    bool eof()const noexcept{return input_eof_&&input_.empty();}
    bool upload_drained()const noexcept{return eof()&&output_.empty();}
    bool poll(){
        if(!message_||output_.size()>524288-65537)return false;
        Bytes question;
        if(udp_){question=std::exchange(input_,{});message_=false;}
        else{if(input_.size()<2){if(input_eof_)throw Failure("DNS_FAILED: incomplete TCP query","DNS_TCP_TRUNCATED");return false;}size_t n=get16(input_);if(n<12)throw Failure("DNS_FAILED: TCP request length","DNS_REQUEST_INVALID");if(input_.size()<n+2){if(input_eof_)throw Failure("DNS_FAILED: incomplete TCP query","DNS_TCP_TRUNCATED");return false;}vpn::consume(input_,2);question=vpn::consume(input_,n);message_=!input_.empty();}
        Bytes answer;try{NativeDohExchange exchange;answer=exchange.query(node_,question,phase_);if(udp_)answer=dns_udp_answer(question,std::move(answer));}
        catch(const std::exception& error){auto cancellation=dynamic_cast<const Failure*>(&error);if(cancellation&&cancellation->code=="CANCELLED")throw;if(failure_)failure_(error);answer=dns_failure_reply(question);}
        if(udp_)output_=std::move(answer);else{be16(output_,answer.size());append(output_,answer);}return true;
    }
};
}
