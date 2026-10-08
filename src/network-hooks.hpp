#pragma once
#include "core-api.h"
#include "provider-module.hpp"
#include <atomic>
#include <mutex>
#include <sstream>
namespace vpn {
struct NetworkHooks {vpn_core_socket_protector protect=nullptr;vpn_core_resolver resolve=nullptr;void* user=nullptr;};
inline NetworkHooks network_hooks;
inline std::mutex network_hooks_mutex;
inline std::atomic<int> core_state{VPN_CORE_STOPPED};
inline std::atomic<uint16_t> core_listen_port{0};
inline int protect_socket_callback(int64_t fd,void*){
    std::lock_guard<std::mutex> lock(network_hooks_mutex);
    if(!network_hooks.protect)return 1;
    try{return network_hooks.protect(fd,network_hooks.user)==1?1:0;}catch(...){return 0;}
}
inline int resolve_callback(const char* host,char* out,int cap,void*){
    std::lock_guard<std::mutex> lock(network_hooks_mutex);
    if(!network_hooks.resolve)return -1;
    try{return network_hooks.resolve(host,out,cap,network_hooks.user);}catch(...){return -1;}
}
inline void configure_network_hooks(const NetworkHooks& hooks){
    using Setter=void(*)(uintptr_t,uintptr_t,uintptr_t);Setter setter=nullptr;
    ProviderModule::instance().symbol(setter,"vpn_socket_set_hooks");
    // Change the provider first: its setter waits for in-flight callbacks.
    setter(0,0,0);
    {std::lock_guard<std::mutex> lock(network_hooks_mutex);network_hooks=hooks;}
    setter(hooks.protect?reinterpret_cast<uintptr_t>(&protect_socket_callback):0,
           hooks.resolve?reinterpret_cast<uintptr_t>(&resolve_callback):0,0);
}
inline std::vector<std::string> bootstrap_addresses(const std::string& host){
    char output[4096];int n;
    {std::lock_guard<std::mutex> lock(network_hooks_mutex);
     if(!network_hooks.resolve)return {host};
     try{n=network_hooks.resolve(host.c_str(),output,sizeof(output),network_hooks.user);}catch(...){n=-1;}}
    if(n<=0||n>=int(sizeof(output)))throw Failure("DNS_FAILED: bootstrap resolver failed","BOOTSTRAP_DNS_FAILED");
    std::istringstream in(std::string(output,size_t(n)));std::vector<std::string> names;std::string name;
    while(std::getline(in,name)){if(!name.empty())names.push_back(name);if(names.size()>32)throw Failure("DNS_FAILED: resolver address limit","BOOTSTRAP_DNS_LIMIT");}
    if(names.empty())throw Failure("DNS_FAILED: bootstrap resolver returned no addresses","BOOTSTRAP_DNS_EMPTY");
    return names;
}
}
