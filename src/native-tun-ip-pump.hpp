// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
// EXPERIMENTAL single-worker packet dispatch: Wintun -> core protocol sessions.
// This class is intentionally NOT invoked by the app SDK/CLI. Do not activate
// routes: DNS/IPv6/kill-switch and full TCP congestion handling are incomplete.
#pragma once
#ifdef _WIN32
#include "native-wintun-session.hpp"
#include "native-tun-tcp-socks.hpp"
#include "native-tun-udp-protocol.hpp"
#include <atomic>
#include <set>
#include <string>
#include <vector>

namespace vpn {
class NativeTunIpPump final {
    NativeWintunSession& wintun_;
    const Config& config_;
    tun_tcp::Reliable tcp_;
    NativeTcpSocksBridge tcp_socks_;
    NativeUdpProtocolBridge udp_;
    std::set<tun_tcp::Key> pending_fin_;
    std::atomic<bool> stop_{false};

    template<class Diagnostic>
    void inject_tcp(const std::vector<uint8_t>& packet,Diagnostic diagnostic) {
        if(packet.empty()||!wintun_.inject_authenticated(packet.data(),packet.size()))
            diagnostic(0,"NATIVE_TCP_PACKET_INJECTION_FAILED");
    }
    template<class Diagnostic>
    void reset_tcp(const tun_tcp::Key& key,Diagnostic diagnostic) {
        auto reset=tcp_.reset(key);
        pending_fin_.erase(key);
        tcp_socks_.close(key);
        if(reset)inject_tcp(*reset,diagnostic);
    }
    template<class Diagnostic>
    void dispatch(tun_tcp::Result result,Diagnostic diagnostic) {
        for(const auto& packet:result.to_tun)inject_tcp(packet,diagnostic);
        for(const auto& event:result.events) {
            try {
                if(event.kind==tun_tcp::Event::Kind::opened) {
                    // Core SOCKS listener is the ONLY TCP destination.
                    // It forwards via the existing authenticated VPN engine.
                    if(!tcp_socks_.open(event.key,core_listen_port.load(),config_.connect_ms))
                        reset_tcp(event.key,diagnostic);
                } else if(event.kind==tun_tcp::Event::Kind::bytes) {
                    if(!tcp_socks_.write(event.key,event.payload.data(),event.payload.size(),
                                         config_.connect_ms))
                        reset_tcp(event.key,diagnostic);
                } else if(event.kind==tun_tcp::Event::Kind::peer_finished) {
                    if(!tcp_socks_.close_upload(event.key))
                        reset_tcp(event.key,diagnostic);
                } else if(event.kind==tun_tcp::Event::Kind::reset) {
                    pending_fin_.erase(event.key);
                    tcp_socks_.close(event.key);
                }
            } catch(const std::exception&) {
                diagnostic(0,"NATIVE_TCP_CORE_BRIDGE_FAILED");
                reset_tcp(event.key,diagnostic);
            }
        }
    }
public:
    NativeTunIpPump(NativeWintunSession& adapter,const Config& config)
        :wintun_(adapter),config_(config),udp_(config){}
    NativeTunIpPump(const NativeTunIpPump&)=delete;
    NativeTunIpPump& operator=(const NativeTunIpPump&)=delete;
    void request_stop()noexcept {stop_.store(true,std::memory_order_relaxed);}
    void clear()noexcept {
        pending_fin_.clear();
        tcp_socks_.clear();
        tcp_.clear();
        udp_.clear();
    }
    size_t tcp_sessions()const noexcept {return tcp_socks_.active_sessions();}
    size_t udp_sessions()const noexcept {return udp_.active_sessions();}
    template<class Diagnostic>
    bool step(Diagnostic diagnostic) {
        if(stop_.load(std::memory_order_relaxed)||stopping.load(std::memory_order_relaxed)){
            clear();return false;
        }
        std::vector<uint8_t> ip_packet;
        NativeTunVerdict verdict=NativeTunVerdict::malformed;
        const auto status=wintun_.read(ip_packet,verdict,20);
        if(status==NativeTunReadStatus::stopped){clear();return false;}
        if(status==NativeTunReadStatus::accepted) {
            if(verdict==NativeTunVerdict::tcp) {
                dispatch(tcp_.receive(ip_packet.data(),ip_packet.size()),diagnostic);
            } else if(verdict==NativeTunVerdict::udp) {
                auto mapped=wintun_.map_udp_request(ip_packet);
                if(mapped) {
                    try {
                        if(!udp_.submit(*mapped))
                            diagnostic(mapped->flow_id,"NATIVE_UDP_SUBMIT_REJECTED");
                    }catch(const std::exception&){
                        diagnostic(mapped->flow_id,"NATIVE_UDP_SUBMIT_FAILED");
                    }
                }
            }
        }
        udp_.poll([&](const NativeUdpProtocolReply& reply){
            if(!wintun_.inject_udp_response(reply.flow_id,reply.address,reply.port,
                                            reply.payload.data(),reply.payload.size()))
                diagnostic(reply.flow_id,"NATIVE_UDP_INJECT_REJECTED");
        },diagnostic);

        std::vector<tun_tcp::Key> failed;
        tcp_socks_.poll(
            [&](const tun_tcp::Key& key){return tcp_.send_capacity(key);},
            [&](const tun_tcp::Key& key,const uint8_t* bytes,size_t count){
                auto packet=tcp_.send(key,bytes,count);
                if(packet)inject_tcp(*packet,diagnostic);
                else failed.push_back(key);
            },
            [&](const tun_tcp::Key& key){pending_fin_.insert(key);},
            [&](const tun_tcp::Key& key,const char*){failed.push_back(key);});
        for(const auto& key:failed)reset_tcp(key,diagnostic);
        dispatch(tcp_.tick(),diagnostic);
        for(auto it=pending_fin_.begin();it!=pending_fin_.end();) {
            auto packet=tcp_.finish(*it);
            if(packet){inject_tcp(*packet,diagnostic);it=pending_fin_.erase(it);}
            else ++it;
        }
        if(stop_.load(std::memory_order_relaxed)||stopping.load(std::memory_order_relaxed)){
            clear();return false;
        }
        return true;
    }
};
} // namespace vpn
#endif
