// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
#include "../src/native-tun-packet.hpp"
#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>

using vpn::NativeTunVerdict;
static std::array<uint8_t,40> tcp() {
    std::array<uint8_t,40> p{};
    p[0]=0x45; p[2]=0; p[3]=40; p[8]=64; p[9]=6;
    p[20]=0x12; p[21]=0x34; p[22]=0x01; p[23]=0xbb;
    p[32]=0x50;
    return p;
}
static std::array<uint8_t,28> udp(uint16_t port) {
    std::array<uint8_t,28> p{};
    p[0]=0x45; p[3]=28; p[8]=64; p[9]=17;
    p[20]=0x12; p[21]=0x34; p[22]=uint8_t(port>>8);p[23]=uint8_t(port);
    p[24]=0; p[25]=8;
    return p;
}
int main() {
    auto t=tcp();
    assert(vpn::inspect_native_tun_packet(t.data(),t.size()).verdict==NativeTunVerdict::tcp);
    t[6]=0x20;
    assert(vpn::inspect_native_tun_packet(t.data(),t.size()).verdict==NativeTunVerdict::fragmented);
    t=tcp(); t[0]=0x4f;
    assert(vpn::inspect_native_tun_packet(t.data(),t.size()).verdict==NativeTunVerdict::malformed);
    t=tcp();t[32]=0x40;
    assert(vpn::inspect_native_tun_packet(t.data(),t.size()).verdict==NativeTunVerdict::malformed);
    auto u=udp(443);
    assert(vpn::inspect_native_tun_packet(u.data(),u.size()).verdict==NativeTunVerdict::blocked_udp_443);
    u=udp(53);
    assert(vpn::inspect_native_tun_packet(u.data(),u.size()).verdict==NativeTunVerdict::udp);
    u[25]=7;
    assert(vpn::inspect_native_tun_packet(u.data(),u.size()).verdict==NativeTunVerdict::malformed);
    u=udp(53);u[0]=0x60;
    assert(vpn::inspect_native_tun_packet(u.data(),u.size()).verdict==NativeTunVerdict::unsupported_ipv6);
    assert(vpn::inspect_native_tun_packet(nullptr,0).verdict==NativeTunVerdict::malformed);
    std::cout<<"PASS: native TUN packet policy probe"<<std::endl;
}
