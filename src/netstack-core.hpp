// Experimental direct packet -> existing C++ protocol engine bridge.
// No SOCKS listener/handshake, alternate VPN engine, subprocess or OS routes.
// Caller owns one serialized worker; connect/poll can wait for the existing
// provider, so this proof is not yet a production packet-loop scheduler.
#pragma once
#include "transport.hpp"
#include "netstack-provider.hpp"
#include "udp-relay.hpp"
#include <map>
#include <memory>

namespace vpn {
class PacketProtocolStream {
    const Config& config_;
    Socket server_;
    SecureStream tls_;
    Transport transport_;
    Protocol protocol_;
    XHttpStream provider_;
    Queue up_;
    Bytes down_,pending_;
    bool provider_path_,upload_closed_=false,finished_=false,eof_=false;
    void decode(const Bytes& wire) {
        auto plain=protocol_.decode(provider_path_?wire:transport_.decode(wire));
        if(protocol_.take_direct()) {
            if(provider_path_)throw Failure("PROTOCOL_FAILED: Vision provider bypass","VISION_DIRECT_SECURITY");
            auto held=tls_.switch_direct_receive();auto direct=protocol_.decode(transport_.decode(held));append(plain,direct);
        }
        if(down_.size()+plain.size()>524288)throw Failure("RELAY_FAILED: stack receive buffer","NETSTACK_BUFFER_LIMIT");
        append(down_,plain);
        auto control=protocol_.take_control();
        if(provider_path_)append(pending_,control);
        else {
            up_.append(tls_.take_control());
            if(!control.empty()&&tls_.write_open())up_.append(tls_.encrypt(transport_.encode(control)));
            auto carrier_control=transport_.take_control();
            if(!carrier_control.empty()&&tls_.write_open())up_.append(tls_.encrypt(carrier_control));
        }
    }
public:
    PacketProtocolStream(const Config& c,const Bytes& destination):config_(c),transport_(c),protocol_(c),provider_path_(c.transport=="xhttp"||c.transport=="http"||c.transport=="kcp"||c.transport=="quic") {
        auto deadline=Clock::now()+std::chrono::milliseconds(c.connect_ms);
        if(provider_path_){provider_.open(c,protocol_.open(destination),deadline);return;}
        server_=connect_server(c,deadline);tls_.handshake(server_,c,deadline);Bytes header;
        if(c.transport=="websocket"&&c.ws_early_data)header=transport_.prepare(protocol_.open(destination));
        auto initial=transport_.open(server_,tls_,deadline,header.empty()?nullptr:&header);
        if(c.transport=="websocket"&&c.ws_early_data){if(!header.empty())send_secure(server_,tls_,transport_.encode_prepared(header),deadline);}
        else send_secure(server_,tls_,transport_.encode(protocol_.open(destination)),deadline);
        decode(initial);
    }
    bool write(const Bytes& plain) {
        if(upload_closed_)throw Failure("RELAY_FAILED: upload closed","NETSTACK_WRITE_CLOSED");
        if(up_.size()+pending_.size()+tls_.pending_bytes()+transport_.pending_bytes()+protocol_.pending_bytes()+plain.size()>524288)return false;
        auto wire=protocol_.encode(plain);
        if(provider_path_)append(pending_,wire);else up_.append(tls_.encrypt(transport_.encode(wire)));
        return true;
    }
    void finish_upload() {
        if(upload_closed_)return;
        upload_closed_=true;auto final=protocol_.finish();
        if(provider_path_)append(pending_,final);else if(!final.empty())up_.append(tls_.encrypt(transport_.encode(final)));
    }
    const Bytes& received()const noexcept{return down_;}
    void consume(size_t n){if(n>down_.size())throw std::logic_error("receive accounting");down_.erase(down_.begin(),down_.begin()+std::ptrdiff_t(n));}
    bool eof()const noexcept{return eof_;}
    void poll() {
        check_cancelled();
        if(provider_path_) {
            if(down_.size()<524288-65536)decode(provider_.read());
            if(!pending_.empty()&&provider_.write(pending_))pending_.clear();
            if(upload_closed_&&!finished_&&pending_.empty()&&!protocol_.pending_bytes()){provider_.finish();finished_=true;}
            eof_=provider_.closed()||protocol_.closed();return;
        }
        if(down_.size()<524288-65536)decode(tls_.feed(nullptr,0));
        if(upload_closed_&&!finished_&&!protocol_.pending_bytes()) {
            auto final=transport_.finish();if(!final.empty())up_.append(tls_.encrypt(final));
            if((config_.transport=="raw"||config_.transport=="httpupgrade"||config_.transport=="obfs-http"||config_.transport=="obfs-tls")&&tls_.secure())up_.append(tls_.close_notify());
            finished_=true;
        }
        if(!up_.empty())up_.flush(server_);
        if(finished_&&up_.empty()&&!tls_.secure()&&(config_.transport=="raw"||config_.transport=="httpupgrade")) {
#ifdef _WIN32
            shutdown(server_.get(),SD_SEND);
#else
            shutdown(server_.get(),SHUT_WR);
#endif
        }
        if(!eof_&&down_.size()<524288-65536)for(unsigned i=0;i<16;++i) {
            uint8_t b[16384];int n=server_.receive(b,sizeof(b));if(n==-2)break;
            if(n==0){eof_=true;if(tls_.secure()&&!tls_.direct_receive()&&!tls_.closed())throw Failure("TLS_FAILED: truncated stream","TLS_TRUNCATED");break;}
            decode(tls_.feed(b,size_t(n)));
        }
        eof_=eof_||tls_.closed()||transport_.closed()||protocol_.closed();
    }
};

class NetstackCoreBridge {
    struct Session {
        NetstackFlow flow;
        Bytes destination,upload,download;
        std::unique_ptr<PacketProtocolStream> stream;
        std::unique_ptr<UdpTunnel> udp;
        std::unique_ptr<ShadowsocksUdp> shadowsocks;
        Socket socket;
        bool input_eof=false,output_eof=false;
        Clock::time_point last=Clock::now();
    };
    const Config& config_;
    NetstackPackets& packets_;
    std::map<uint64_t,std::unique_ptr<Session>> sessions_;
public:
    NetstackCoreBridge(const Config& config,NetstackPackets& packets):config_(config),packets_(packets){require_supported(config_);}
    ~NetstackCoreBridge(){for(const auto& s:sessions_)packets_.api().drop(packets_.id(),s.first);}
    size_t active_sessions()const noexcept{return sessions_.size();}
    void poll() {
        check_cancelled();
        // A real TUN deployment must supply OS protector/bootstrap hooks.
        {std::lock_guard<std::mutex> lock(network_hooks_mutex);if(!network_hooks.protect||!network_hooks.resolve)throw Failure("CONNECT_FAILED: packet engine hooks required","NETSTACK_NETWORK_HOOKS_REQUIRED");}
        auto& api=packets_.api();const auto id=packets_.id();NetstackFlow flow;
        for(unsigned i=0;i<16;++i) {
            int code=api.accept(id,&flow);if(code==-2)break;if(code!=1)throw Failure("PROTOCOL_FAILED: accept flow","NETSTACK_ACCEPT");
            auto s=std::make_unique<Session>();s->flow=flow;s->destination=netstack_destination(flow);
            try {
                if(flow.protocol==6)s->stream=std::make_unique<PacketProtocolStream>(config_,s->destination);
                else if(flow.protocol==17){if(config_.protocol=="ss"){s->socket=connect_udp_server(config_);s->shadowsocks=std::make_unique<ShadowsocksUdp>(config_);}else s->udp=std::make_unique<UdpTunnel>(config_,s->destination);}
                else throw Failure("PROTOCOL_FAILED: flow protocol","NETSTACK_FLOW_PROTOCOL");
                sessions_.emplace(flow.id,std::move(s));
            }catch(...){api.drop(id,flow.id);throw;}
        }
        for(auto it=sessions_.begin();it!=sessions_.end();) {
            auto& s=*it->second;
            if(Clock::now()-s.last>std::chrono::milliseconds(config_.idle_ms)){api.drop(id,it->first);it=sessions_.erase(it);continue;}
            if(s.upload.empty()&&!s.input_eof) {
                uint8_t b[65535];int n=api.read(id,it->first,b,sizeof(b));
                if(n==-4){s.input_eof=true;if(s.stream)s.stream->finish_upload();}
                else if(n>=0){s.upload.assign(b,b+n);s.last=Clock::now();
                    // Empty UDP datagrams must be sent once, not mistaken for EOF.
                    if(s.flow.protocol==17){if(s.shadowsocks){auto wire=s.shadowsocks->encode(Datagram{s.destination,s.upload});int sent=s.socket.send(wire.data(),wire.size());if(sent!=int(wire.size()))throw Failure("RELAY_FAILED: UDP send","NETSTACK_UDP_SEND");}else s.udp->send(s.upload);s.upload.clear();}}
                else if(n!=-2)throw Failure("RELAY_FAILED: flow read","NETSTACK_FLOW_READ");
            }
            if(s.stream) {
                if(!s.upload.empty()&&s.stream->write(s.upload))s.upload.clear();
                s.stream->poll();auto& data=s.stream->received();
                if(!data.empty()){int n=api.write(id,it->first,data.data(),int(std::min(data.size(),size_t(65507))));if(n>=0){s.stream->consume(size_t(n));s.last=Clock::now();}else if(n!=-2)throw Failure("RELAY_FAILED: flow write","NETSTACK_FLOW_WRITE");}
                if(s.stream->eof()&&s.stream->received().empty()&&!s.output_eof){if(api.shutdown_write(id,it->first))throw Failure("RELAY_FAILED: half-close","NETSTACK_HALF_CLOSE");s.output_eof=true;}
                if(s.input_eof&&s.output_eof){api.release(id,it->first);it=sessions_.erase(it);continue;}
            } else {
                if(s.download.empty()) {
                    std::vector<Datagram> replies;
                    if(s.shadowsocks){uint8_t b[65535];int n=s.socket.receive(b,sizeof(b));if(n>=0)replies.push_back(s.shadowsocks->decode(Bytes(b,b+n)));}
                    else replies=s.udp->poll();
                    // Keep all datagrams bounded; no concatenation across records.
                    for(const auto& d:replies){if(d.address!=s.destination)throw Failure("PROTOCOL_FAILED: wrong UDP endpoint","NETSTACK_UDP_ENDPOINT");int n=api.write(id,it->first,d.payload.data(),int(d.payload.size()));if(n!=int(d.payload.size()))throw Failure("RELAY_FAILED: UDP output backpressure","NETSTACK_UDP_OUTPUT");s.last=Clock::now();}
                }
            }
            ++it;
        }
    }
};
}
