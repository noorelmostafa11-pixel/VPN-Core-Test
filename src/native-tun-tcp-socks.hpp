// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
// Experimental in-process TCP -> EXISTING core SOCKS5 listener bridge.
// It only connects to 127.0.0.1; the existing core engine owns proxy encryption.
// Does not own a TUN adapter, route, DNS or production TCP/IP stack.
#pragma once
#include "transport.hpp"
#include "native-tun-tcp-reliable.hpp"
#include <algorithm>
#include <array>
#include <map>
#include <mutex>
#include <stdexcept>
#include <utility>
#include <vector>

namespace vpn {
class NativeTcpSocksBridge final {
    struct Session {
        Socket socket;
        bool write_closed=false;
        explicit Session(Socket&& s):socket(std::move(s)){}
    };
    std::map<tun_tcp::Key,Session> sessions_;
    static constexpr size_t capacity_=64;
    static constexpr size_t read_limit_=536;

    static Socket local_connection(uint16_t port,Clock::time_point deadline) {
        if(!port)throw Failure("CONNECT_FAILED: missing local SOCKS listener","NATIVE_TCP_SOCKS_PORT");
        Socket client(::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP));
        if(client.get()==invalid_socket)
            throw Failure("CONNECT_FAILED: cannot open loopback socket","NATIVE_TCP_LOOPBACK_SOCKET");
        nonblocking(client.get());
        sockaddr_in target{};
        target.sin_family=AF_INET;
        target.sin_port=htons(port);
        target.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        const int code=::connect(client.get(),reinterpret_cast<sockaddr*>(&target),sizeof(target));
        if(code!=0&&!would_block(socket_error()))
            throw Failure("CONNECT_FAILED: cannot reach core SOCKS listener","NATIVE_TCP_LOOPBACK_CONNECT");
        if(code!=0) {
            wait_socket(client.get(),true,deadline);
            int error=0;
#ifdef _WIN32
            int length=sizeof(error);
#else
            socklen_t length=sizeof(error);
#endif
            if(getsockopt(client.get(),SOL_SOCKET,SO_ERROR,
                          reinterpret_cast<char*>(&error),&length)!=0||error)
                throw Failure("CONNECT_FAILED: local SOCKS listener rejected connection","NATIVE_TCP_LOOPBACK_CONNECT");
        }
        return client;
    }
    static void handshake(Socket& socket,const tun_tcp::Key& key,Clock::time_point deadline) {
        const uint8_t greeting[]{5,1,0};
        send_all(socket,greeting,sizeof(greeting),deadline);
        const auto welcome=receive_exact(socket,2,deadline);
        if(welcome!=Bytes{5,0})
            throw Failure("PROTOCOL_FAILED: local SOCKS method rejected","NATIVE_TCP_SOCKS_GREETING");
        const uint8_t request[]{5,1,0,1,key.dst[0],key.dst[1],key.dst[2],key.dst[3],
                                uint8_t(key.destination_port>>8),uint8_t(key.destination_port)};
        send_all(socket,request,sizeof(request),deadline);
        const auto head=receive_exact(socket,4,deadline);
        if(head[0]!=5||head[1]!=0||head[2]!=0)
            throw Failure("CONNECT_FAILED: core SOCKS proxy rejected destination","NATIVE_TCP_SOCKS_REJECTED");
        size_t address_bytes=0;
        if(head[3]==1)address_bytes=4;
        else if(head[3]==4)address_bytes=16;
        else if(head[3]==3)address_bytes=receive_exact(socket,1,deadline)[0];
        else throw Failure("PROTOCOL_FAILED: malformed core SOCKS reply","NATIVE_TCP_SOCKS_REPLY");
        (void)receive_exact(socket,address_bytes+2,deadline);
    }
    static void require_protected_core() {
        std::lock_guard<std::mutex> lock(network_hooks_mutex);
        if(!network_hooks.protect||!network_hooks.resolve)
            throw Failure("CONNECT_FAILED: native TCP requires protected core sockets and bootstrap DNS",
                          "NATIVE_TCP_NETWORK_HOOKS_REQUIRED");
    }
public:
    size_t active_sessions() const noexcept {return sessions_.size();}
    void clear() noexcept {sessions_.clear();}
    void close(const tun_tcp::Key& key) noexcept {sessions_.erase(key);}
    // Called only after the native TCP handshake. Never dial the destination
    // directly. The existing engine must already have a bound SOCKS port.
    bool open(const tun_tcp::Key& key,uint16_t local_socks_port,unsigned timeout_ms=5000) {
        if(!key.source_port||!key.destination_port||!local_socks_port)return false;
        if(sessions_.count(key))return true;
        if(sessions_.size()>=capacity_)return false;
        require_protected_core();
        check_cancelled();
        const auto deadline=Clock::now()+std::chrono::milliseconds(timeout_ms);
        auto socket=local_connection(local_socks_port,deadline);
        handshake(socket,key,deadline);
        sessions_.emplace(std::piecewise_construct,
                          std::forward_as_tuple(key),
                          std::forward_as_tuple(std::move(socket)));
        return true;
    }
    bool write(const tun_tcp::Key& key,const uint8_t* data,size_t bytes,unsigned timeout_ms=5000) {
        auto it=sessions_.find(key);
        if(it==sessions_.end()||it->second.write_closed||(!data&&bytes)||
           bytes>1460)return false;
        if(!bytes)return true;
        send_all(it->second.socket,data,bytes,
                 Clock::now()+std::chrono::milliseconds(timeout_ms));
        return true;
    }
    bool close_upload(const tun_tcp::Key& key) {
        auto it=sessions_.find(key);
        if(it==sessions_.end())return false;
        if(it->second.write_closed)return true;
#ifdef _WIN32
        if(::shutdown(it->second.socket.get(),SD_SEND)!=0)
#else
        if(::shutdown(it->second.socket.get(),SHUT_WR)!=0)
#endif
            throw Failure("RELAY_FAILED: cannot half-close loopback SOCKS stream",
                          "NATIVE_TCP_SOCKS_HALF_CLOSE");
        it->second.write_closed=true;
        return true;
    }
    // The can_read callback enforces TUN-side ACK/backpressure. When false,
    // this method does NOT read/discard bytes from the SOCKS socket.
    template<class Ready,class Data,class End,class FailureNote>
    void poll(Ready can_read,Data deliver,End ended,FailureNote failed) {
        for(auto it=sessions_.begin();it!=sessions_.end();) {
            check_cancelled();
            const auto& key=it->first;
            if(!can_read(key)){++it;continue;}
            try {
                uint8_t b[read_limit_]{};
                const int n=it->second.socket.receive(b,sizeof(b));
                if(n==-2){++it;continue;}
                if(n==0){ended(key);it=sessions_.erase(it);continue;}
                deliver(key,b,size_t(n));
                ++it;
            }catch(const std::exception&){
                failed(key,"NATIVE_TCP_SOCKS_RELAY");
                it=sessions_.erase(it);
            }
        }
    }
};
} // namespace vpn
