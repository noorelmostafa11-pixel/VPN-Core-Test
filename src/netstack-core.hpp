// Experimental direct packet -> existing C++ protocol engine bridge.
// No SOCKS listener/handshake, alternate VPN engine, subprocess or OS routes.
// Packet dispatch never waits for protocol connection creation. A bounded
// set of joinable flow workers owns protocol state; short ABI calls serialize
// packet/endpoint access. Stop joins workers before the stack or hooks retire.
#pragma once
#include "transport.hpp"
#include "netstack-provider.hpp"
#include "udp-relay.hpp"
#include <map>
#include <memory>
#include <thread>
#include <deque>
#include <condition_variable>
#include <functional>

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
        std::thread worker;
        std::atomic<bool> stop{false},done{false};
        std::atomic<uint64_t> packet_wakes{0};
        std::mutex wait_mutex;
        std::condition_variable wake;
        ~Session(){stop=true;wake.notify_all();if(worker.joinable())worker.join();}
    };
    const Config& config_;
    NetstackPackets& packets_;
    size_t maximum_;
    std::map<uint64_t,std::unique_ptr<Session>> sessions_;
    std::function<void(uint64_t,const std::string&)> diagnostic_;
    std::atomic<uint64_t> upload_{0},download_{0},udp_dropped_{0},failures_{0};
    template<class F>auto call(F f){std::lock_guard<std::mutex> lock(packets_.calls());return f(packets_.api(),packets_.id());}
    void worker(Session& s)noexcept {
        bool graceful=false;
        try {
            auto destination=netstack_destination(s.flow);
            std::unique_ptr<PacketProtocolStream> stream;
            std::unique_ptr<UdpTunnel> udp;
            std::unique_ptr<ShadowsocksUdp> ss;
            Socket socket;
            if(s.flow.protocol==6)stream=std::make_unique<PacketProtocolStream>(config_,destination);
            else if(s.flow.protocol==17){if(config_.protocol=="ss"){socket=connect_udp_server(config_);ss=std::make_unique<ShadowsocksUdp>(config_);}else udp=std::make_unique<UdpTunnel>(config_,destination);}
            else throw Failure("PROTOCOL_FAILED: flow protocol","NETSTACK_FLOW_PROTOCOL");
            Bytes upload,ss_wire;bool upload_present=false,input_eof=false,output_eof=false;
            std::deque<Bytes> replies;size_t reply_bytes=0;auto last=Clock::now();
            while(!s.stop&&!stopping) {
                check_cancelled();bool progress=false;const auto wake_at=s.packet_wakes.load();
                if(Clock::now()-last>std::chrono::milliseconds(config_.idle_ms))throw Failure("RELAY_FAILED: flow idle timeout","NETSTACK_IDLE_TIMEOUT");
                // TCP stops consuming its endpoint when the carrier applies
                // backpressure. UDP records (including zero bytes) stay distinct.
                if(!upload_present&&!input_eof&&(!udp||udp->pending_bytes()<524288-131072)) {
                    uint8_t b[65535];int n=call([&](NetstackAPI& a,uint64_t id){return a.read(id,s.flow.id,b,sizeof(b));});
                    if(n==-4){input_eof=true;if(stream)stream->finish_upload();progress=true;}
                    else if(n>=0){upload.assign(b,b+n);upload_present=true;progress=true;}
                    else if(n!=-2)throw Failure("RELAY_FAILED: flow read","NETSTACK_FLOW_READ");
                }
                if(stream) {
                    if(upload_present&&stream->write(upload)){upload_+=upload.size();upload.clear();upload_present=false;progress=true;}
                    stream->poll();const auto& data=stream->received();
                    if(!data.empty()) {
                        int n=call([&](NetstackAPI& a,uint64_t id){return a.write(id,s.flow.id,data.data(),int(std::min(data.size(),size_t(65507))));});
                        if(n>0){stream->consume(size_t(n));download_+=uint64_t(n);progress=true;}
                        else if(n!=-2&&n!=0)throw Failure("RELAY_FAILED: flow write","NETSTACK_FLOW_WRITE");
                    }
                    if(stream->eof()&&stream->received().empty()&&!output_eof){if(call([&](NetstackAPI& a,uint64_t id){return a.shutdown_write(id,s.flow.id);}))throw Failure("RELAY_FAILED: half-close","NETSTACK_HALF_CLOSE");output_eof=true;progress=true;}
                    if(input_eof&&output_eof){graceful=true;break;}
                } else {
                    if(upload_present) {
                        if(ss) {
                            if(ss_wire.empty())ss_wire=ss->encode(Datagram{destination,upload});
                            int n=socket.send(ss_wire.data(),ss_wire.size());
                            if(n==int(ss_wire.size())){ss_wire.clear();upload_+=upload.size();upload.clear();upload_present=false;progress=true;}
                            else if(n!=-2)throw Failure("RELAY_FAILED: UDP send","NETSTACK_UDP_SEND");
                        }else{udp->send(upload);upload_+=upload.size();upload.clear();upload_present=false;progress=true;}
                    }
                    std::vector<Datagram> incoming;
                    if(ss){uint8_t b[65535];int n=socket.receive(b,sizeof(b));if(n>=0)incoming.push_back(ss->decode(Bytes(b,b+n)));}
                    else incoming=udp->poll();
                    for(auto& d:incoming) {
                        if(d.address!=destination)throw Failure("PROTOCOL_FAILED: wrong UDP endpoint","NETSTACK_UDP_ENDPOINT");
                        // UDP cannot backpressure its remote sender. Drop newest
                        // on overflow, account it, and never truncate/concatenate.
                        if(d.payload.size()>65507||replies.size()>=32||reply_bytes+d.payload.size()>524288){++udp_dropped_;continue;}
                        reply_bytes+=d.payload.size();replies.push_back(std::move(d.payload));progress=true;
                    }
                    for(unsigned i=0;i<16&&!replies.empty();++i) {
                        const auto& p=replies.front();int n=call([&](NetstackAPI& a,uint64_t id){return a.write(id,s.flow.id,p.data(),int(p.size()));});
                        if(n==-2)break;if(n!=int(p.size()))throw Failure("RELAY_FAILED: UDP output","NETSTACK_UDP_OUTPUT");
                        download_+=p.size();reply_bytes-=p.size();replies.pop_front();progress=true;
                    }
                }
                if(progress){last=Clock::now();continue;}
                std::unique_lock<std::mutex> wait(s.wait_mutex);
                s.wake.wait_for(wait,std::chrono::milliseconds(1),[&]{return s.stop.load()||stopping.load()||s.packet_wakes.load()!=wake_at;});
            }
        }catch(const std::exception& e){++failures_;auto f=dynamic_cast<const Failure*>(&e);if(diagnostic_)try{diagnostic_(s.flow.id,f?f->code:"NETSTACK_CARRIER_FAILED");}catch(...){} }
        catch(...){++failures_;if(diagnostic_)try{diagnostic_(s.flow.id,"NETSTACK_WORKER_FAILED");}catch(...){} }
        try{call([&](NetstackAPI& a,uint64_t id){if(graceful)a.release(id,s.flow.id);else a.drop(id,s.flow.id);return 0;});}catch(...){}
        s.done=true;
    }
public:
    NetstackCoreBridge(const Config& config,NetstackPackets& packets,size_t maximum=64,
        std::function<void(uint64_t,const std::string&)> diagnostic={})
        :config_(config),packets_(packets),maximum_(std::min(maximum,size_t(config.max_connections))),diagnostic_(std::move(diagnostic)) {
        require_supported(config_);if(maximum_<1||maximum_>256)throw Failure("STARTUP_FAILED: flow limit","NETSTACK_FLOW_LIMIT");
        std::lock_guard<std::mutex> lock(network_hooks_mutex);
        if(!network_hooks.protect||!network_hooks.resolve)throw Failure("STARTUP_FAILED: packet engine hooks required","NETSTACK_NETWORK_HOOKS_REQUIRED");
    }
    ~NetstackCoreBridge(){stop();}
    void stop()noexcept {
        for(auto& pair:sessions_){pair.second->stop=true;pair.second->wake.notify_all();}
        sessions_.clear(); // joins before packets_ is destroyed
    }
    // Called only by the packet owner after a bounded injection batch.
    void notify_packets()noexcept {
        for(auto& pair:sessions_){++pair.second->packet_wakes;pair.second->wake.notify_one();}
    }
    size_t active_sessions()const noexcept{return sessions_.size();}
    Json metrics(){Json j=packets_.metrics();j["cpp_uploaded_bytes"]=Json::integer(upload_.load());j["cpp_downloaded_bytes"]=Json::integer(download_.load());j["udp_queue_dropped_records"]=Json::integer(udp_dropped_.load());j["flow_failures"]=Json::integer(failures_.load());j["maximum_workers"]=Json::integer(maximum_);return j;}
    void poll() {
        check_cancelled();
        for(auto it=sessions_.begin();it!=sessions_.end();)if(it->second->done){it=sessions_.erase(it);}else ++it;
        for(unsigned i=0;i<16;++i) {
            NetstackFlow flow;int n=call([&](NetstackAPI& a,uint64_t id){return a.accept(id,&flow);});
            if(n==-2)break;if(n!=1)throw Failure("PROTOCOL_FAILED: accept flow","NETSTACK_ACCEPT");
            if(sessions_.size()>=maximum_){call([&](NetstackAPI& a,uint64_t id){a.drop(id,flow.id);return 0;});continue;}
            auto s=std::make_unique<Session>();s->flow=flow;auto* state=s.get();
            try{state->worker=std::thread([this,state]{worker(*state);});sessions_.emplace(flow.id,std::move(s));}
            catch(...){call([&](NetstackAPI& a,uint64_t id){a.drop(id,flow.id);return 0;});throw;}
        }
    }
};
}
