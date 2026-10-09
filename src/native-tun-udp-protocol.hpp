// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
// An experimental in-core UDP transport bridge. No adapter/routes are activated.
// One caller-owned worker must call submit/poll/clear serially.
// Every flow gets its own protocol session to prevent reply cross-talk.
#pragma once
#include "native-tun-udp.hpp"
#include "udp-relay.hpp"
#include <array>
#include <algorithm>
#include <functional>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

namespace vpn {
struct NativeUdpProtocolReply {
    uint64_t flow_id=0;
    tun_udp::IPv4 address{};
    uint16_t port=0;
    Bytes payload;
};

// Insists on the exact IPv4 endpoint from the TUN request. A reply carrying
// another host or port is never eligible for injection into the TUN.
inline bool native_udp_reply_matches(const Bytes& address,
                                    const tun_udp::IPv4& expected_ip,
                                    uint16_t expected_port) noexcept {
    return address.size()==7 && address[0]==1 &&
        std::equal(expected_ip.begin(),expected_ip.end(),address.begin()+1) &&
        (uint16_t(uint16_t(address[5])<<8|address[6])==expected_port);
}
class NativeUdpProtocolBridge final {
    struct Session {
        uint64_t flow_id=0;
        Bytes address;
        tun_udp::IPv4 ip{};
        uint16_t port=0;
        Clock::time_point last=Clock::now();
        std::unique_ptr<UdpTunnel> tunnel;
        std::unique_ptr<ShadowsocksUdp> shadowsocks;
        Socket socket;
    };
    const Config& config_;
    std::map<uint64_t,std::unique_ptr<Session>> sessions_;
    static constexpr size_t limit_=64;
    static constexpr size_t maximum_datagram_=65507;

    static bool valid_destination(const tun_udp::Outbound& packet) noexcept {
        const auto& a=packet.socks_destination;
        if(packet.flow_id==0||a.size()!=7||a[0]!=1||packet.destination_port==0||
           packet.destination_port==443||packet.payload.size()>maximum_datagram_)
            return false;
        return native_udp_reply_matches(a,packet.destination,packet.destination_port);
    }
public:
    explicit NativeUdpProtocolBridge(const Config& config):config_(config){}
    NativeUdpProtocolBridge(const NativeUdpProtocolBridge&)=delete;
    NativeUdpProtocolBridge& operator=(const NativeUdpProtocolBridge&)=delete;
    size_t active_sessions() const noexcept{return sessions_.size();}
    void clear() noexcept {sessions_.clear();}

    // Rejects malformed/inconsistent requests before any socket is created.
    // Network sockets use the core's existing protector and bootstrap resolver;
    // the caller MUST also pin the VPN endpoint outside any later TUN routes.
    bool submit(const tun_udp::Outbound& packet) {
        if(!valid_destination(packet))return false;
        check_cancelled();
        auto it=sessions_.find(packet.flow_id);
        if(it==sessions_.end()) {
            if(sessions_.size()>=std::min(limit_,size_t(config_.max_connections)))
                return false;
            auto created=std::make_unique<Session>();
            created->flow_id=packet.flow_id;
            created->address=packet.socks_destination;
            created->ip=packet.destination;
            created->port=packet.destination_port;
            if(config_.protocol=="ss") {
                // Shadowsocks uses native encrypted UDP, not the stream UdpTunnel.
                created->socket=connect_udp_server(config_);
                created->shadowsocks=std::make_unique<ShadowsocksUdp>(config_);
            } else {
                // Reuse the existing VMess/VLESS/Trojan authenticated UDP path.
                created->tunnel=std::make_unique<UdpTunnel>(config_,created->address);
            }
            it=sessions_.emplace(packet.flow_id,std::move(created)).first;
        } else if(it->second->ip!=packet.destination ||
                  it->second->port!=packet.destination_port ||
                  it->second->address!=packet.socks_destination) {
            return false;
        }
        Session& session=*it->second;
        session.last=Clock::now();
        try {
            if(session.shadowsocks) {
                Datagram datagram{session.address,packet.payload};
                auto wire=session.shadowsocks->encode(datagram);
                const auto sent=::send(session.socket.get(),
                                      reinterpret_cast<const char*>(wire.data()),
                                      int(wire.size()),0);
                // A blocked/short UDP send is not a successful datagram.
                if(sent!=int(wire.size())) {
                    if(sent<0 && !would_block(socket_error()))
                        throw Failure("RELAY_FAILED: native TUN UDP send","UDP_SEND_FAILED",uint32_t(socket_error()));
                    return false;
                }
            } else {
                session.tunnel->send(packet.payload);
            }
            return true;
        } catch(...) {
            sessions_.erase(it);
            throw;
        }
    }

    // Results are authenticated/decoded by the existing protocol engine. A
    // strictly matched flow_id+destination is still required by TUN injection.
    // A slow provider transport can block here: this experimental bridge must
    // not run on the UI thread and is NOT yet suitable for activating routes.
    template<class Deliver,class Diagnostic>
    void poll(Deliver deliver,Diagnostic diagnostic) {
        check_cancelled();
        for(auto it=sessions_.begin();it!=sessions_.end();) {
            check_cancelled();
            Session& session=*it->second;
            auto expired=Clock::now()-session.last>=std::chrono::seconds(60);
            if(expired) {it=sessions_.erase(it);continue;}
            try {
                auto receive=[&](const Datagram& datagram) {
                    if(!native_udp_reply_matches(datagram.address,session.ip,session.port))
                        return;
                    // Never deliver a response for another source/port.
                    deliver(NativeUdpProtocolReply{session.flow_id,session.ip,
                                                   session.port,datagram.payload});
                    session.last=Clock::now();
                };
                if(session.shadowsocks) {
                    for(unsigned n=0;n<16;++n) {
                        uint8_t buffer[65536];
                        const int count=session.socket.receive(buffer,sizeof(buffer));
                        if(count==-2)break;
                        if(count<=0)break;
                        receive(session.shadowsocks->decode(Bytes(buffer,buffer+count)));
                    }
                } else {
                    for(const auto& datagram:session.tunnel->poll())receive(datagram);
                }
                ++it;
            } catch(const std::exception& error) {
                const auto failure=dynamic_cast<const Failure*>(&error);
                diagnostic(session.flow_id,failure?failure->code:"UDP_RELAY_FAILED");
                it=sessions_.erase(it);
            }
        }
    }
};
} // namespace vpn
