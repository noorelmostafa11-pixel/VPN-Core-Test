#pragma once
#include "core-api.h"
#include "provider-module.hpp"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>
#include <utility>
#include <vector>
namespace vpn {
using HookClock=std::chrono::steady_clock;
struct NetworkHooks {vpn_core_socket_protector protect=nullptr;vpn_core_resolver resolve=nullptr;void* user=nullptr;};
inline NetworkHooks network_hooks;
inline std::mutex network_hooks_mutex;
inline std::condition_variable network_hooks_idle;
inline unsigned network_hooks_active=0,network_dns_active=0;
inline bool network_hooks_accepting=true;
inline std::atomic<unsigned> network_dns_timeout{10000};
inline std::atomic<bool> stopping{false};
inline std::atomic<int> core_state{VPN_CORE_STOPPED};
inline std::atomic<uint16_t> core_listen_port{0};
inline void check_cancelled(){if(stopping.load(std::memory_order_relaxed))throw Failure("CANCELLED: operation stopped","CANCELLED");}
// A lease keeps the caller-owned user context alive until run_config drains.
// Registry locks protect bookkeeping only; application code never runs under them.
struct HookLease {
    NetworkHooks hooks;bool dns;
    explicit HookLease(bool lookup):dns(lookup){
        std::lock_guard<std::mutex> lock(network_hooks_mutex);
        if(!network_hooks_accepting||stopping)throw Failure("CANCELLED: hooks stopping","CANCELLED");
        if(dns&&network_dns_active>=16)throw Failure("DNS_FAILED: callback capacity exhausted","DNS_CALLBACK_BUSY");
        hooks=network_hooks;++network_hooks_active;if(dns)++network_dns_active;
    }
    ~HookLease(){std::lock_guard<std::mutex> lock(network_hooks_mutex);--network_hooks_active;if(dns)--network_dns_active;network_hooks_idle.notify_all();}
    HookLease(const HookLease&)=delete;
};
inline bool has_bootstrap_resolver(){std::lock_guard<std::mutex> lock(network_hooks_mutex);return network_hooks.resolve!=nullptr;}
inline int protect_socket_callback(int64_t fd,void*){
    try{HookLease lease(false);if(!lease.hooks.protect)return 1;auto result=lease.hooks.protect(fd,lease.hooks.user);return !stopping&&result==1?1:0;}catch(...){return 0;}
}
struct DnsResult {std::mutex mutex;std::condition_variable ready;bool done=false;std::atomic<bool> finished{false};int size=-1;char output[4096]{};};
// Callback completion is not native-thread completion. Keep joinable workers
// until their thread-local cleanup has finished, including timed-out requests.
struct DnsWorker {
    std::shared_ptr<DnsResult> result;std::thread thread;std::mutex join_mutex;
    ~DnsWorker(){if(thread.joinable())thread.join();}
};
inline std::mutex dns_workers_mutex;
inline std::vector<std::shared_ptr<DnsWorker>> dns_workers;
inline void join_dns_worker(const std::shared_ptr<DnsWorker>& worker){
    // Only workers whose callback has returned are reaped during operation.
    // This per-worker lock never blocks another DNS request or registry access.
    {std::lock_guard<std::mutex> lock(worker->join_mutex);if(worker->thread.joinable())worker->thread.join();}
    std::lock_guard<std::mutex> lock(dns_workers_mutex);
    for(auto it=dns_workers.begin();it!=dns_workers.end();++it)if(*it==worker){dns_workers.erase(it);break;}
}
inline void reap_dns_workers(bool drain=false){
    for(;;){std::shared_ptr<DnsWorker> retired;
        {std::lock_guard<std::mutex> lock(dns_workers_mutex);
            for(const auto& worker:dns_workers)if(drain||worker->result->finished.load(std::memory_order_acquire)){retired=worker;break;}}
        if(!retired)return;join_dns_worker(retired);
    }
}
template<class Task>inline std::shared_ptr<DnsWorker> launch_dns_worker(const std::shared_ptr<DnsResult>& result,Task task){
    reap_dns_workers();auto worker=std::make_shared<DnsWorker>();worker->result=result;
    std::lock_guard<std::mutex> lock(dns_workers_mutex);dns_workers.push_back(worker);
    try{worker->thread=std::thread([result,task=std::move(task)]()mutable{
        try{task();}catch(...){std::lock_guard<std::mutex> lock(result->mutex);result->size=-1;result->done=true;}
        result->finished.store(true,std::memory_order_release);result->ready.notify_all();
    });}catch(...){dns_workers.pop_back();throw;}
    return worker;
}
inline std::string invoke_bootstrap(const std::string& host,HookClock::time_point deadline){
    check_cancelled();auto lease=std::make_shared<HookLease>(true);
    if(!lease->hooks.resolve)return host;
    auto result=std::make_shared<DnsResult>();
    auto worker=launch_dns_worker(result,[lease,result,host]{
        int n=-1;try{n=lease->hooks.resolve(host.c_str(),result->output,sizeof(result->output),lease->hooks.user);}catch(...){}
        {std::lock_guard<std::mutex> lock(result->mutex);result->size=n;result->done=true;}result->ready.notify_all();
        // lease is released only after the callback no longer uses host/output/user.
    });
    std::unique_lock<std::mutex> lock(result->mutex);
    while(!result->done){check_cancelled();if(HookClock::now()>=deadline)throw Failure("DNS_FAILED: bootstrap callback timeout","BOOTSTRAP_DNS_TIMEOUT");result->ready.wait_until(lock,std::min(deadline,HookClock::now()+std::chrono::milliseconds(20)));}
    check_cancelled();auto n=result->size;
    lock.unlock();join_dns_worker(worker);
    if(n<=0||n>=int(sizeof(result->output)))throw Failure("DNS_FAILED: bootstrap resolver failed","BOOTSTRAP_DNS_FAILED");
    return std::string(result->output,size_t(n));
}
inline int resolve_callback(const char* host,char* out,int cap,void*){
    try{auto text=invoke_bootstrap(host,HookClock::now()+std::chrono::milliseconds(network_dns_timeout));if(text.size()>=size_t(cap))return -1;std::memcpy(out,text.data(),text.size());return int(text.size());}catch(const Failure& error){return error.code=="BOOTSTRAP_DNS_TIMEOUT"?-2:error.code=="CANCELLED"?-3:error.code=="DNS_CALLBACK_BUSY"?-4:-1;}catch(...){return -1;}
}
inline void cancel_provider_network(){using Cancel=void(*)();Cancel cancel=nullptr;ProviderModule::instance().symbol(cancel,"vpn_socket_cancel");cancel();}
inline void configure_network_hooks(const NetworkHooks& hooks,bool start=false){
    using Setter=void(*)(uintptr_t,uintptr_t,uintptr_t);Setter setter=nullptr;ProviderModule::instance().symbol(setter,"vpn_socket_set_hooks");
    {std::lock_guard<std::mutex> lock(network_hooks_mutex);network_hooks_accepting=false;}
    setter(0,0,0); // Go also drains leases without holding a lock over callbacks.
    {std::unique_lock<std::mutex> lock(network_hooks_mutex);network_hooks_idle.wait(lock,[]{return network_hooks_active==0;});}
    // No callback or thread may still use the old application's context when
    // run_config returns. Join without holding either shared registry lock.
    reap_dns_workers(true);
    {std::lock_guard<std::mutex> lock(network_hooks_mutex);network_hooks=hooks;network_hooks_accepting=true;}
    if(start){using Start=void(*)();Start begin=nullptr;ProviderModule::instance().symbol(begin,"vpn_socket_start");begin();}
    setter(hooks.protect?reinterpret_cast<uintptr_t>(&protect_socket_callback):0,hooks.resolve?reinterpret_cast<uintptr_t>(&resolve_callback):0,0);
}
inline std::vector<std::string> bootstrap_addresses(const std::string& host,HookClock::time_point deadline){
    if(!has_bootstrap_resolver())return {host};
    auto text=invoke_bootstrap(host,deadline);std::istringstream in(text);std::vector<std::string> names;std::string name;
    while(std::getline(in,name)){if(!name.empty())names.push_back(name);if(names.size()>32)throw Failure("DNS_FAILED: resolver address limit","BOOTSTRAP_DNS_LIMIT");}
    if(names.empty())throw Failure("DNS_FAILED: resolver returned no addresses","BOOTSTRAP_DNS_EMPTY");return names;
}
}
