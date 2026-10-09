// Experimental additive ABI; same provider module/runtime as TLS and HTTP.
#pragma once
#include "provider-module.hpp"
#include <cstdint>
#include <mutex>
#ifndef _WIN32
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#endif
namespace vpn {
struct alignas(8) NetstackFlow {
    uint64_t id=0;
    uint32_t protocol=0,address_size=0;
    uint8_t address[16]{};
    uint16_t port=0,reserved=0;
};
static_assert(sizeof(NetstackFlow)==40,"Go/C++ flow ABI layout");
class NetstackAPI {
public:
    int(*abi)()=nullptr;
    uint64_t(*create)(int,int)=nullptr;
    void(*close)(uint64_t)=nullptr;
    int(*inject)(uint64_t,const uint8_t*,int)=nullptr;
    int(*packet)(uint64_t,uint8_t*,int)=nullptr;
    int(*accept)(uint64_t,NetstackFlow*)=nullptr;
    int(*read)(uint64_t,uint64_t,uint8_t*,int)=nullptr;
    int(*write)(uint64_t,uint64_t,const uint8_t*,int)=nullptr;
    int(*shutdown_write)(uint64_t,uint64_t)=nullptr;
    void(*drop)(uint64_t,uint64_t)=nullptr;
    void(*release)(uint64_t,uint64_t)=nullptr;
    int(*metrics)(uint64_t,uint8_t*,int)=nullptr;
    int(*set_wakeup)(uint64_t,int64_t)=nullptr;
    int(*copy_probe)(const uint8_t*,uint8_t*,int)=nullptr;
    NetstackAPI() {
        auto& p=ProviderModule::instance();
        p.symbol(abi,"vpn_tun_abi_version");
        if(abi()!=1)throw Failure("PROTOCOL_FAILED: packet stack ABI","NETSTACK_ABI_VERSION");
        p.symbol(create,"vpn_tun_create");p.symbol(close,"vpn_tun_close");
        p.symbol(inject,"vpn_tun_inject");p.symbol(packet,"vpn_tun_packet");
        p.symbol(accept,"vpn_tun_accept");p.symbol(read,"vpn_tun_read");
        p.symbol(write,"vpn_tun_write");p.symbol(shutdown_write,"vpn_tun_shutdown_write");
        p.symbol(drop,"vpn_tun_drop");p.symbol(metrics,"vpn_tun_metrics");
        p.symbol(release,"vpn_tun_release");
        p.symbol(copy_probe,"vpn_tun_copy_probe");p.symbol(set_wakeup,"vpn_tun_set_wakeup");
    }
};
class NetstackWakeup {
#ifdef _WIN32
    HANDLE event_=nullptr;
#else
    int pipe_[2]{-1,-1};
#endif
public:
    NetstackWakeup(){
#ifdef _WIN32
        event_=CreateEventW(nullptr,FALSE,FALSE,nullptr);if(!event_)throw Failure("STARTUP_FAILED: stack wake event","NETSTACK_WAKE_EVENT",GetLastError());
#else
        if(pipe2(pipe_,O_NONBLOCK|O_CLOEXEC)<0)throw Failure("STARTUP_FAILED: stack wake pipe","NETSTACK_WAKE_PIPE",errno);
#endif
    }
    ~NetstackWakeup(){
#ifdef _WIN32
        if(event_)CloseHandle(event_);
#else
        if(pipe_[0]>=0)::close(pipe_[0]);if(pipe_[1]>=0)::close(pipe_[1]);
#endif
    }
    NetstackWakeup(const NetstackWakeup&)=delete;
    int64_t wait_handle()const noexcept {
#ifdef _WIN32
        return int64_t(reinterpret_cast<uintptr_t>(event_));
#else
        return pipe_[0];
#endif
    }
    int64_t signal_handle()const noexcept {
#ifdef _WIN32
        return wait_handle();
#else
        return pipe_[1];
#endif
    }
    // Consume only BEFORE draining the packet/accept queues; never after them.
    void consume()noexcept {
#ifdef _WIN32
        WaitForSingleObject(event_,0);
#else
        uint64_t values[64];for(;;){auto n=::read(pipe_[0],values,sizeof(values));if(n<0&&errno==EINTR)continue;if(n<=0)break;}
#endif
    }
};
class NetstackPackets {
    NetstackAPI api_;
    std::mutex calls_;
    NetstackWakeup wakeup_;
    uint64_t id_=0;
public:
    explicit NetstackPackets(int mtu=1500,int flows=64):id_(api_.create(mtu,flows)) {
        if(!id_)throw Failure("PROTOCOL_FAILED: packet stack create","NETSTACK_CREATE");
        if(api_.set_wakeup(id_,wakeup_.signal_handle())){api_.close(id_);id_=0;throw Failure("STARTUP_FAILED: stack wake binding","NETSTACK_WAKE_BIND");}
    }
    ~NetstackPackets(){api_.close(id_);} // Go drains/disables notification before wakeup_ closes.
    void consume_wakeup()noexcept{wakeup_.consume();}
    int64_t wake_handle()const noexcept{return wakeup_.wait_handle();}
    NetstackPackets(const NetstackPackets&)=delete;
    NetstackPackets& operator=(const NetstackPackets&)=delete;
    uint64_t id()const noexcept{return id_;}
    std::mutex& calls()noexcept{return calls_;}
    NetstackAPI& api()noexcept{return api_;}
    void inject(const Bytes& p){std::lock_guard<std::mutex> lock(calls_);if(api_.inject(id_,p.data(),int(p.size()))!=int(p.size()))throw Failure("PROTOCOL_FAILED: packet rejected","NETSTACK_PACKET_INPUT");}
    bool packet(Bytes& p){std::lock_guard<std::mutex> lock(calls_);p.resize(65535);int n=api_.packet(id_,p.data(),int(p.size()));if(n==-2){p.clear();return false;}if(n<0)throw Failure("PROTOCOL_FAILED: packet output","NETSTACK_PACKET_OUTPUT");p.resize(size_t(n));return true;}
    Json metrics(){std::lock_guard<std::mutex> lock(calls_);uint8_t b[4096];int n=api_.metrics(id_,b,sizeof(b));if(n<0)throw Failure("PROTOCOL_FAILED: stack metrics","NETSTACK_METRICS");return json_parse(std::string(reinterpret_cast<char*>(b),size_t(n)));}
};
inline Bytes netstack_destination(const NetstackFlow& f) {
    if((f.address_size!=4&&f.address_size!=16)||!f.port)throw Failure("PROTOCOL_FAILED: flow destination","NETSTACK_DESTINATION");
    Bytes out{uint8_t(f.address_size==4?1:4)};
    out.insert(out.end(),f.address,f.address+f.address_size);be16(out,f.port);return out;
}
}
