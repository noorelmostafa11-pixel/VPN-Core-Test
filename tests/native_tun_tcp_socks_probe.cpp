// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
// Independent local SOCKS peer: no VPN node, Wintun adapter, DNS or route change.
#include "../src/native-tun-tcp-socks.hpp"
#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>
using namespace vpn;
static int allow_protected(int64_t,void*) {return 1;}
static int bootstrap(const char*,char* out,int capacity,void*) {
    const char address[]="127.0.0.1\n";
    if(capacity<int(sizeof(address)))return -1;
    std::memcpy(out,address,sizeof(address)-1);
    return int(sizeof(address)-1);
}
int main() {
    [[maybe_unused]] NetworkRuntime winsock;
    NativeTcpSocksBridge bridge;
    const tun_tcp::Key key{{198,18,0,2},{8,8,8,8},43128,80};
    // Without both network protection callbacks, the bridge cannot start.
    bool blocked=false;
    try {(void)bridge.open(key,42000,250);}
    catch(const Failure& e){blocked=e.code=="NATIVE_TCP_NETWORK_HOOKS_REQUIRED";}
    assert(blocked&&bridge.active_sessions()==0);

    {
        std::lock_guard<std::mutex> lock(network_hooks_mutex);
        network_hooks.protect=&allow_protected;
        network_hooks.resolve=&bootstrap;
    }
    Socket listener=listen_local(0);
    sockaddr_in address{};
#ifdef _WIN32
    int length=sizeof(address);
#else
    socklen_t length=sizeof(address);
#endif
    if(getsockname(listener.get(),reinterpret_cast<sockaddr*>(&address),&length))
        throw std::runtime_error("listener port missing");
    const uint16_t port=ntohs(address.sin_port);
    std::exception_ptr peer_failure;
    std::thread peer([&] {
        try {
            const auto deadline=Clock::now()+std::chrono::seconds(5);
            wait_socket(listener.get(),false,deadline);
            Socket server(::accept(listener.get(),nullptr,nullptr));
            if(server.get()==invalid_socket)throw std::runtime_error("mock accept failed");
            nonblocking(server.get());
            if(receive_exact(server,3,deadline)!=Bytes{5,1,0})
                throw std::runtime_error("unexpected SOCKS greeting");
            const uint8_t welcome[]{5,0};
            send_all(server,welcome,sizeof(welcome),deadline);
            const auto request=receive_exact(server,10,deadline);
            if(request!=Bytes({5,1,0,1,8,8,8,8,0,80}))
                throw std::runtime_error("SOCKS bridge attempted wrong destination");
            const uint8_t reply[]{5,0,0,1,127,0,0,1,0,0};
            send_all(server,reply,sizeof(reply),deadline);
            auto data=receive_exact(server,4,deadline);
            if(data!=Bytes({'p','i','n','g'}))
                throw std::runtime_error("mock received wrong data");
            const uint8_t response[]{'p','o','n','g'};
            send_all(server,response,sizeof(response),deadline);
            uint8_t buffer[1];
            while(true) {
                const int n=server.receive(buffer,sizeof(buffer));
                if(n==0)break;
                if(n==-2){wait_socket(server.get(),false,deadline);continue;}
                throw std::runtime_error("unexpected extra data");
            }
        } catch(...) {peer_failure=std::current_exception();}
    });
    try {
        assert(bridge.open(key,port,3000));
        assert(bridge.active_sessions()==1);
        assert(bridge.write(key,reinterpret_cast<const uint8_t*>("ping"),4,3000));
        bool got_reply=false;
        for(unsigned i=0;i<100&&!got_reply;++i) {
            bridge.poll([](const tun_tcp::Key&){return size_t(536);},
                [&](const tun_tcp::Key& got,const uint8_t* data,size_t n){
                    assert(!(got<key)&&!(key<got));
                    got_reply=n==4&&std::equal(data,data+n,"pong");},
                [&](const tun_tcp::Key&){},
                [&](const tun_tcp::Key&,const char*){throw std::runtime_error("Unexpected loopback error");});
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        assert(got_reply);
        assert(bridge.close_upload(key));
        peer.join();
        if(peer_failure)std::rethrow_exception(peer_failure);
        bridge.close(key);
        assert(bridge.active_sessions()==0);
    }catch(...){
        bridge.clear();
        if(peer.joinable())peer.join();
        throw;
    }
    {
        std::lock_guard<std::mutex> lock(network_hooks_mutex);
        network_hooks={};
    }
    std::cout<<"PASS: native TCP bridges TUN destinations through loopback SOCKS; rejects missing hooks; preserves data and half-close\n";
}
