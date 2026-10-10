// Experimental direct packet -> existing C++ protocol engine bridge.
// No SOCKS listener/handshake, alternate VPN engine, subprocess or OS routes.
// Packet dispatch never waits for protocol connection creation. A bounded
// set of joinable flow workers owns protocol state; short ABI calls serialize
// packet/endpoint access. Stop joins workers before the stack or hooks retire.
#pragma once
#include "transport.hpp"
#include "netstack-provider.hpp"
#include "udp-relay.hpp"
#include "native-tun-dns.hpp"
#include <map>
#include <memory>
#include <thread>
#include <deque>
#include <condition_variable>
#include <functional>

namespace vpn {
struct FlowFailure {
    uint64_t id;
    uint32_t protocol,address_size;
    uint16_t port;
    const char* phase;
    std::string reason;
    uint32_t native_status;
};

class NetstackCoreBridge {
    struct Session {
        NetstackFlow flow;
        std::thread worker;
        std::atomic<bool> stop{false},done{false};
        std::atomic<uint64_t> packet_wakes{0};
        std::mutex wait_mutex;
        std::condition_variable wake;bool provider_polling=true;
#ifdef _WIN32
        HANDLE packet_event=nullptr,idle_timer=nullptr;
        WSAEVENT carrier_event=WSA_INVALID_EVENT;
        Handle carrier=invalid_socket;
        Session(){
            packet_event=CreateEventW(nullptr,FALSE,FALSE,nullptr);
            if(!packet_event)throw Failure("STARTUP_FAILED: flow wake event","NETSTACK_FLOW_WAIT",GetLastError());
        }
#endif
        void watch_carrier(Handle socket,bool polling=true){
            provider_polling=polling;
#ifdef _WIN32
            if(socket==invalid_socket){ // asynchronous providers retain bounded polling
                if(!provider_polling)return;
                idle_timer=CreateWaitableTimerExW(nullptr,nullptr,0x00000002,TIMER_MODIFY_STATE|SYNCHRONIZE);
                if(!idle_timer)throw Failure("STARTUP_FAILED: precise flow wait","NETSTACK_FLOW_WAIT",GetLastError());return;
            }
            carrier_event=WSACreateEvent();if(carrier_event==WSA_INVALID_EVENT)throw Failure("STARTUP_FAILED: carrier event","NETSTACK_CARRIER_EVENT",WSAGetLastError());
            if(WSAEventSelect(socket,carrier_event,FD_READ|FD_WRITE|FD_CLOSE))throw Failure("STARTUP_FAILED: carrier readiness","NETSTACK_CARRIER_EVENT",WSAGetLastError());
            carrier=socket;
#else
            (void)socket;
#endif
        }
        void notify()noexcept{
#ifdef _WIN32
            SetEvent(packet_event);
#else
            wake.notify_all();
#endif
        }
        void idle(uint64_t observed){
#ifdef _WIN32
            if(stop||stopping||packet_wakes.load()!=observed)return;
            if(carrier!=invalid_socket){
                // Network readiness and injected packets wake this specific
                // worker. The timeout only bounds cancellation/idle checks.
                HANDLE events[]{packet_event,carrier_event};auto result=WaitForMultipleObjects(2,events,FALSE,20);
                if(result==WAIT_FAILED)throw Failure("RELAY_FAILED: carrier wait","NETSTACK_FLOW_WAIT",GetLastError());
                if(result==WAIT_OBJECT_0+1){WSANETWORKEVENTS network{};if(WSAEnumNetworkEvents(carrier,carrier_event,&network))throw Failure("RELAY_FAILED: carrier events","NETSTACK_CARRIER_EVENT",WSAGetLastError());}
                return;
            }
            if(!provider_polling){if(WaitForSingleObject(packet_event,20)==WAIT_FAILED)throw Failure("RELAY_FAILED: DNS wake","NETSTACK_FLOW_WAIT",GetLastError());return;}
            LARGE_INTEGER due{};due.QuadPart=-10000; // one-shot 1 ms; no global timer-resolution change
            if(!SetWaitableTimer(idle_timer,&due,0,nullptr,nullptr,FALSE))throw Failure("RELAY_FAILED: flow timer","NETSTACK_FLOW_TIMER",GetLastError());
            HANDLE events[]{packet_event,idle_timer};auto result=WaitForMultipleObjects(2,events,FALSE,INFINITE);CancelWaitableTimer(idle_timer);
            if(result==WAIT_FAILED)throw Failure("RELAY_FAILED: flow wait","NETSTACK_FLOW_WAIT",GetLastError());
#else
            std::unique_lock<std::mutex> wait(wait_mutex);
            wake.wait_for(wait,std::chrono::milliseconds(provider_polling?1:20),[&]{return stop.load()||stopping.load()||packet_wakes.load()!=observed;});
#endif
        }
        ~Session(){stop=true;notify();if(worker.joinable())worker.join();
#ifdef _WIN32
            if(carrier_event!=WSA_INVALID_EVENT)WSACloseEvent(carrier_event);
            if(idle_timer)CloseHandle(idle_timer);CloseHandle(packet_event);
#endif
        }
    };
    const Config& config_;
    NetstackPackets& packets_;
    size_t maximum_;
    std::map<uint64_t,std::unique_ptr<Session>> sessions_;
    std::function<void(const FlowFailure&)> diagnostic_;
    std::atomic<uint64_t> upload_{0},download_{0},udp_dropped_{0},failures_{0},cancelled_{0},rejected_{0},dns_failures_{0};
    template<class F>auto call(F f){std::lock_guard<std::mutex> lock(packets_.calls());return f(packets_.api(),packets_.id());}
    void worker(Session& s)noexcept {
        bool graceful=false,cancelled=false;const char* phase="CONNECT";
        auto diagnose=[&](const std::string& reason,uint32_t status=0){if(diagnostic_)try{diagnostic_(FlowFailure{s.flow.id,s.flow.protocol,s.flow.address_size,s.flow.port,phase,reason,status});}catch(...){}};
        try {
            auto destination=netstack_destination(s.flow);
            std::unique_ptr<PacketProtocolStream> stream;std::unique_ptr<NativeDnsSession> dns;
            std::unique_ptr<UdpTunnel> udp;
            std::unique_ptr<ShadowsocksUdp> ss;
            Socket socket;
            if(native_dns_flow(s.flow))dns=std::make_unique<NativeDnsSession>(config_,s.flow.protocol==17,&phase,[&](const std::exception& error){
                ++dns_failures_;auto failure=dynamic_cast<const Failure*>(&error);diagnose(failure?failure->code:"DNS_UPSTREAM_FAILED",failure?failure->native_status:0);
            });
            else if(s.flow.protocol==6)stream=std::make_unique<PacketProtocolStream>(config_,destination,&phase);
            else if(s.flow.protocol==17){if(config_.protocol=="ss"){socket=connect_udp_server(config_);ss=std::make_unique<ShadowsocksUdp>(config_);}else udp=std::make_unique<UdpTunnel>(config_,destination,s.flow.address_size==16?65527:65507,&phase);}
            else throw Failure("PROTOCOL_FAILED: flow protocol","NETSTACK_FLOW_PROTOCOL");
            phase="RELAY";s.watch_carrier(dns?invalid_socket:stream?stream->carrier_handle():udp?udp->carrier_handle():socket.get(),!dns);
            Bytes upload,ss_wire;bool upload_present=false,input_eof=false,output_eof=false;
            std::deque<Bytes> replies;size_t reply_bytes=0;auto last=Clock::now();
            while(!s.stop&&!stopping) {
                check_cancelled();bool progress=false;const auto wake_at=s.packet_wakes.load();
                if((!dns||s.flow.protocol==6)&&Clock::now()-last>std::chrono::milliseconds(config_.idle_ms))throw Failure("RELAY_FAILED: flow idle timeout","NETSTACK_IDLE_TIMEOUT");
                // TCP stops consuming its endpoint when the carrier applies
                // backpressure. UDP records (including zero bytes) stay distinct.
                if(!upload_present&&!input_eof&&(!udp||udp->pending_bytes()<524288-131072)) {
                    uint8_t b[65535];int n=call([&](NetstackAPI& a,uint64_t id){return a.read(id,s.flow.id,b,sizeof(b));});
                    if(n==-4){input_eof=true;if(stream)stream->finish_upload();else if(dns)dns->finish_upload();progress=true;}
                    else if(n>=0){upload.assign(b,b+n);upload_present=true;progress=true;}
                    else if(n!=-2)throw Failure("RELAY_FAILED: flow read","NETSTACK_FLOW_READ");
                }
                if(stream||(dns&&s.flow.protocol==6)) {
                    if(upload_present&&(dns?dns->write(upload):stream->write(upload))){upload_+=upload.size();upload.clear();upload_present=false;progress=true;}
                    progress=(dns?dns->poll():stream->poll())||progress;const auto& data=dns?dns->received():stream->received();
                    if(!data.empty()) {
                        int n=call([&](NetstackAPI& a,uint64_t id){return a.write(id,s.flow.id,data.data(),int(std::min(data.size(),size_t(65507))));});
                        if(n>0){if(dns)dns->consume(size_t(n));else stream->consume(size_t(n));download_+=uint64_t(n);progress=true;}
                        else if(n!=-2&&n!=0)throw Failure("RELAY_FAILED: flow write","NETSTACK_FLOW_WRITE");
                    }
                    if((dns?dns->eof():stream->eof())&&(dns?dns->received():stream->received()).empty()&&!output_eof){if(call([&](NetstackAPI& a,uint64_t id){return a.shutdown_write(id,s.flow.id);}))throw Failure("RELAY_FAILED: half-close","NETSTACK_HALF_CLOSE");output_eof=true;progress=true;}
                    if(input_eof&&output_eof&&(dns?dns->upload_drained():stream->upload_drained())){graceful=true;break;}
                } else {
                    if(upload_present&&dns){if(dns->write(upload)){upload_+=upload.size();upload.clear();upload_present=false;progress=true;}}
                    else if(upload_present) {
                        if(ss) {
                            if(ss_wire.empty())ss_wire=ss->encode(Datagram{destination,upload});
                            int n=socket.send(ss_wire.data(),ss_wire.size());
                            if(n==int(ss_wire.size())){ss_wire.clear();upload_+=upload.size();upload.clear();upload_present=false;progress=true;}
                            else if(n!=-2)throw Failure("RELAY_FAILED: UDP send","NETSTACK_UDP_SEND");
                        }else{udp->send(upload);upload_+=upload.size();upload.clear();upload_present=false;progress=true;}
                    }
                    std::vector<Datagram> incoming;
                    if(dns){if(dns->poll()){incoming.push_back(Datagram{destination,dns->datagram()});progress=true;}}
                    else if(ss){uint8_t b[65535];int n=socket.receive(b,sizeof(b));if(n>=0)incoming.push_back(ss->decode(Bytes(b,b+n)));}
                    else {auto queued=udp->pending_bytes();incoming=udp->poll();if(udp->pending_bytes()!=queued)progress=true;}
                    for(auto& d:incoming) {
                        if(d.address!=destination)throw Failure("PROTOCOL_FAILED: wrong UDP endpoint","NETSTACK_UDP_ENDPOINT");
                        // UDP cannot backpressure its remote sender. Drop newest
                        // on overflow, account it, and never truncate/concatenate.
                        const size_t maximum_datagram=s.flow.address_size==16?65527:65507;
                        if(d.payload.size()>maximum_datagram||replies.size()>=32||reply_bytes+d.payload.size()>524288){++udp_dropped_;continue;}
                        reply_bytes+=d.payload.size();replies.push_back(std::move(d.payload));progress=true;
                    }
                    for(unsigned i=0;i<16&&!replies.empty();++i) {
                        const auto& p=replies.front();int n=call([&](NetstackAPI& a,uint64_t id){return a.write(id,s.flow.id,p.data(),int(p.size()));});
                        if(n==-2)break;if(n!=int(p.size()))throw Failure("RELAY_FAILED: UDP output","NETSTACK_UDP_OUTPUT");
                        download_+=p.size();reply_bytes-=p.size();replies.pop_front();progress=true;
                    }
                }
                if(progress){last=Clock::now();continue;}
                if(dns&&s.flow.protocol==17&&Clock::now()-last>std::chrono::seconds(2)){graceful=true;break;}
                s.idle(wake_at);
            }
            if(!graceful&&(s.stop||stopping))cancelled=true;
        }catch(const std::exception& e){auto f=dynamic_cast<const Failure*>(&e);if(f&&f->code=="CANCELLED")cancelled=true;else{++failures_;diagnose(f?f->code:"NETSTACK_CARRIER_FAILED",f?f->native_status:0);} }
        catch(...){++failures_;diagnose("NETSTACK_WORKER_FAILED"); }
        if(cancelled){++cancelled_;diagnose("CANCELLED");}
        try{call([&](NetstackAPI& a,uint64_t id){if(graceful)a.release(id,s.flow.id);else a.drop(id,s.flow.id);return 0;});}catch(...){}
        s.done=true;
    }
public:
    NetstackCoreBridge(const Config& config,NetstackPackets& packets,size_t maximum=64,
        std::function<void(const FlowFailure&)> diagnostic={})
        :config_(config),packets_(packets),maximum_(std::min(maximum,size_t(config.max_connections))),diagnostic_(std::move(diagnostic)) {
        require_supported(config_);if(maximum_<1||maximum_>256)throw Failure("STARTUP_FAILED: flow limit","NETSTACK_FLOW_LIMIT");
        std::lock_guard<std::mutex> lock(network_hooks_mutex);
        if(!network_hooks.protect||!network_hooks.resolve)throw Failure("STARTUP_FAILED: packet engine hooks required","NETSTACK_NETWORK_HOOKS_REQUIRED");
    }
    ~NetstackCoreBridge(){stop();}
    void stop()noexcept {
        for(auto& pair:sessions_){pair.second->stop=true;pair.second->notify();}
        sessions_.clear(); // joins before packets_ is destroyed
    }
    // Called only by the packet owner after a bounded injection batch.
    void notify_packets()noexcept {
        for(auto& pair:sessions_){++pair.second->packet_wakes;pair.second->notify();}
    }
    size_t active_sessions()const noexcept{return sessions_.size();}
    Json metrics(){Json j=packets_.metrics();j["cpp_uploaded_bytes"]=Json::integer(upload_.load());j["cpp_downloaded_bytes"]=Json::integer(download_.load());j["udp_queue_dropped_records"]=Json::integer(udp_dropped_.load());j["flow_failures"]=Json::integer(failures_.load());j["dns_request_failures"]=Json::integer(dns_failures_.load());j["cancelled_flows"]=Json::integer(cancelled_.load());j["cpp_rejected_flows"]=Json::integer(rejected_.load());j["maximum_workers"]=Json::integer(maximum_);return j;}
    void poll() {
        check_cancelled();
        for(auto it=sessions_.begin();it!=sessions_.end();)if(it->second->done){it=sessions_.erase(it);}else ++it;
        for(unsigned i=0;i<16;++i) {
            NetstackFlow flow;int n=call([&](NetstackAPI& a,uint64_t id){return a.accept(id,&flow);});
            if(n==-2)break;if(n!=1)throw Failure("PROTOCOL_FAILED: accept flow","NETSTACK_ACCEPT");
            if(sessions_.size()>=maximum_){++rejected_;call([&](NetstackAPI& a,uint64_t id){a.drop(id,flow.id);return 0;});continue;}
            auto s=std::make_unique<Session>();s->flow=flow;auto* state=s.get();
            try{state->worker=std::thread([this,state]{worker(*state);});sessions_.emplace(flow.id,std::move(s));}
            catch(...){call([&](NetstackAPI& a,uint64_t id){a.drop(id,flow.id);return 0;});throw;}
        }
    }
};
}
