// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
// Experimental per-session Windows Wintun <-> core UDP transport pump.
// This class is NOT an active VPN: TCP, IPv6, route control and kill switch
// are unimplemented. Do not activate any full-tunnel routes with this pump.
#pragma once
#ifdef _WIN32
#include "native-wintun-session.hpp"
#include "native-tun-udp-protocol.hpp"
#include <atomic>
#include <functional>
#include <string>
#include <vector>

namespace vpn {
class NativeTunUdpPump final {
    NativeWintunSession& adapter_;
    NativeUdpProtocolBridge bridge_;
    std::atomic<bool> stop_{false};
public:
    NativeTunUdpPump(NativeWintunSession& adapter,const Config& config)
        :adapter_(adapter),bridge_(config){}
    NativeTunUdpPump(const NativeTunUdpPump&)=delete;
    NativeTunUdpPump& operator=(const NativeTunUdpPump&)=delete;

    void request_stop() noexcept {stop_.store(true,std::memory_order_relaxed);}
    void clear() noexcept {bridge_.clear();}
    size_t active_udp_sessions() const noexcept {return bridge_.active_sessions();}

    // Call from ONE owned I/O worker only, never from the UI thread.
    // A caller must supply an out-of-tunnel endpoint route, validated DNS
    // policy and a kill switch before enabling any system routes.
    // Stop/adapter destruction requires joining that worker first.
    template<class Diagnostic>
    bool step(Diagnostic diagnostic) {
        if(stop_.load(std::memory_order_relaxed)||stopping.load(std::memory_order_relaxed)) {
            clear();return false;
        }
        std::vector<uint8_t> packet;
        NativeTunVerdict verdict=NativeTunVerdict::malformed;
        const auto status=adapter_.read(packet,verdict,20);
        if(status==NativeTunReadStatus::stopped) {clear();return false;}
        if(status==NativeTunReadStatus::accepted) {
            if(verdict==NativeTunVerdict::udp) {
                auto mapped=adapter_.map_udp_request(packet);
                if(mapped) {
                    try {
                        if(!bridge_.submit(*mapped))diagnostic(mapped->flow_id,"UDP_SUBMIT_REJECTED");
                    } catch(const std::exception& ex) {
                        // Do not log packet contents or proxy credentials.
                        diagnostic(mapped->flow_id,"UDP_SUBMIT_FAILED");
                    }
                } else diagnostic(0,"UDP_INVALID_IP_PACKET");
            } else if(verdict==NativeTunVerdict::tcp) {
                // Explicitly reject TCP until the TCP/IP stack is ready.
                diagnostic(0,"NATIVE_TCP_NOT_IMPLEMENTED");
            }
        }
        bridge_.poll([&](const NativeUdpProtocolReply& reply) {
            if(!adapter_.inject_udp_response(reply.flow_id,reply.address,reply.port,
                                               reply.payload.data(),reply.payload.size()))
                diagnostic(reply.flow_id,"UDP_INJECT_REJECTED");
        },diagnostic);
        if(stop_.load(std::memory_order_relaxed)||stopping.load(std::memory_order_relaxed)){
            clear();return false;
        }
        return true;
    }
};
} // namespace vpn
#endif
