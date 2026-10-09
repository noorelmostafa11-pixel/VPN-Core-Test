// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
// Isolated contract probe: never creates a Wintun adapter or network socket.
#include "../src/native-tun-udp-protocol.hpp"
#include <iostream>
#include <stdexcept>

int main() {
    const vpn::tun_udp::IPv4 ip{1,1,1,1};
    const vpn::Bytes destination{1,1,1,1,1,0,53};
    const vpn::Bytes spoof{1,8,8,8,8,0,53};
    if(!vpn::native_udp_reply_matches(destination,ip,53) ||
       vpn::native_udp_reply_matches(spoof,ip,53) ||
       vpn::native_udp_reply_matches(destination,ip,443) ||
       vpn::native_udp_reply_matches(vpn::Bytes{1,1,1,1,1,0},ip,53))
        throw std::runtime_error("TUN UDP endpoint binding failed");

    vpn::Config config;
    config.protocol="vless";
    config.max_connections=64;
    vpn::NativeUdpProtocolBridge bridge(config);
    vpn::tun_udp::Outbound packet;
    packet.flow_id=1;
    packet.destination=ip;
    packet.destination_port=53;
    packet.socks_destination=destination;
    packet.payload={42};
    // Default native engine hooks are intentionally null: full-tunnel traffic
    // MUST fail closed before any network socket or OS resolver is accessed.
    bool refused=false;
    try { (void)bridge.submit(packet); }
    catch(const vpn::Failure& failure) {
        refused=failure.code=="NATIVE_TUN_NETWORK_HOOKS_REQUIRED";
    }
    if(!refused||bridge.active_sessions()!=0)
        throw std::runtime_error("Native TUN unprotected network path was not rejected");

    packet.socks_destination=spoof;
    if(bridge.submit(packet))
        throw std::runtime_error("Spoofed destination accepted");
    packet.socks_destination=destination;
    packet.destination_port=443;
    if(bridge.submit(packet))
        throw std::runtime_error("UDP/443 accepted");
    bridge.clear();
    std::cout<<"PASS: native UDP encrypted-path hook requirement and endpoint matching\n";
}
