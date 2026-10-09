// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
// Packet validation and fail-closed policy for a future in-process TUN engine.
// This stage deliberately does not open system routes or forward packets.
#pragma once
#include <cstddef>
#include <cstdint>

namespace vpn {
enum class NativeTunVerdict : uint8_t {
    malformed, unsupported_ipv6, fragmented, blocked_udp_443,
    tcp, udp, unsupported_protocol
};
struct NativeTunPacket {
    NativeTunVerdict verdict=NativeTunVerdict::malformed;
    uint8_t version=0, protocol=0;
    uint16_t source_port=0, destination_port=0;
    size_t network_header_bytes=0, packet_bytes=0;
};
inline uint16_t native_tun_be16(const uint8_t* p) {
    return uint16_t((uint16_t(p[0])<<8)|p[1]);
}
inline NativeTunPacket inspect_native_tun_packet(const uint8_t* p, size_t length) {
    NativeTunPacket result;
    if(!p||length<1||length>65535)return result;
    result.version=uint8_t(p[0]>>4);
    if(result.version==6) {
        // Until an IPv6 TCP/IP stack, routing and DNS protection exist, fail closed.
        result.verdict=NativeTunVerdict::unsupported_ipv6;
        return result;
    }
    if(result.version!=4||length<20)return result;
    const size_t header_bytes=size_t(p[0]&15)*4;
    if(header_bytes<20||header_bytes>60||length<header_bytes)return result;
    const size_t total=native_tun_be16(p+2);
    if(total!=length||total<header_bytes)return result;
    result.network_header_bytes=header_bytes;
    result.packet_bytes=total;
    result.protocol=p[9];
    // Fragmented datagrams cannot be classified by destination port safely.
    if((native_tun_be16(p+6)&0x3fff)!=0) {
        result.verdict=NativeTunVerdict::fragmented;
        return result;
    }
    if(result.protocol!=6&&result.protocol!=17) {
        result.verdict=NativeTunVerdict::unsupported_protocol;
        return result;
    }
    const size_t segment_length=total-header_bytes;
    const size_t minimum=result.protocol==6?20:8;
    if(segment_length<minimum)return result;
    const uint8_t* segment=p+header_bytes;
    result.source_port=native_tun_be16(segment);
    result.destination_port=native_tun_be16(segment+2);
    if(result.source_port==0||result.destination_port==0)return result;
    if(result.protocol==6) {
        const size_t tcp_header_bytes=size_t(segment[12]>>4)*4;
        if(tcp_header_bytes<20||tcp_header_bytes>segment_length)return result;
        result.verdict=NativeTunVerdict::tcp;
        return result;
    }
    // UDP length is mandatory for IPv4, including UDP/53 DNS packets.
    if(native_tun_be16(segment+4)!=segment_length)return result;
    result.verdict=result.destination_port==443?
        NativeTunVerdict::blocked_udp_443:NativeTunVerdict::udp;
    return result;
}
} // namespace vpn
