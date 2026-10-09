// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
// IPv4 UDP datagram codec and bounded flow mapping for experimental native TUN.
// No sockets, DNS fallback, adapter manipulation or direct network path exist here.
#pragma once
#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <iterator>
#include <stdexcept>
#include <vector>

namespace vpn {
namespace tun_udp {
using IPv4 = std::array<uint8_t,4>;
using Clock = std::chrono::steady_clock;

inline uint16_t be16(const uint8_t* p) noexcept {
    return uint16_t((uint16_t(p[0])<<8)|p[1]);
}
inline void put16(uint8_t* p,uint16_t n) noexcept {
    p[0]=uint8_t(n>>8);p[1]=uint8_t(n);
}
inline uint32_t add_words(uint32_t sum,const uint8_t* p,size_t n) noexcept {
    for(size_t i=0;i+1<n;i+=2)sum+=be16(p+i);
    if(n&1)sum+=uint32_t(p[n-1])<<8;
    return sum;
}
inline uint16_t finalize_checksum(uint32_t sum) noexcept {
    while(sum>>16)sum=(sum&0xffffu)+(sum>>16);
    return uint16_t(~sum);
}
inline uint16_t checksum(const uint8_t* p,size_t n) noexcept {
    return finalize_checksum(add_words(0,p,n));
}
inline uint16_t udp_checksum(const IPv4& source,const IPv4& destination,
                             const uint8_t* udp,size_t length) noexcept {
    uint32_t sum=0;
    sum=add_words(sum,source.data(),source.size());
    sum=add_words(sum,destination.data(),destination.size());
    sum+=17u;sum+=uint32_t(length);
    return finalize_checksum(add_words(sum,udp,length));
}
struct Outbound {
    uint64_t flow_id=0;
    IPv4 destination{};
    uint16_t destination_port=0;
    std::vector<uint8_t> socks_destination; // RFC 1928 ATYP+IPv4+port
    std::vector<uint8_t> payload;
};
struct Flow {
    uint64_t id=0;
    IPv4 source{},destination{};
    uint16_t source_port=0,destination_port=0;
    Clock::time_point last{};
};
class Flows {
    static constexpr size_t max_flows_=256;
    static constexpr auto ttl_=std::chrono::seconds(60);
    std::vector<Flow> flows_;
    uint64_t next_id_=1;
    uint16_t next_packet_id_=1;
    void sweep(Clock::time_point now) {
        flows_.erase(std::remove_if(flows_.begin(),flows_.end(),[&](const Flow& f){return now-f.last>=ttl_;}),flows_.end());
    }
public:
    size_t size() const noexcept {return flows_.size();}
    // Single-worker contract. Caller must forward to an authenticated core UDP
    // path and use flow_id to authorize any corresponding response.
    std::optional<Outbound> accept(const uint8_t* p,size_t n,Clock::time_point now=Clock::now()) {
        if(!p||n<28||n>65535||p[0]>>4!=4)return std::nullopt;
        const size_t ihl=size_t(p[0]&15)*4;
        if(ihl<20||ihl>60||n<ihl+8||be16(p+2)!=n||p[9]!=17||p[8]==0)
            return std::nullopt;
        if((be16(p+6)&0x3fffu)!=0||checksum(p,ihl)!=0)return std::nullopt;
        const uint8_t* u=p+ihl;
        const size_t len=n-ihl;
        if(be16(u+4)!=len||be16(u)==0||be16(u+2)==0||be16(u+2)==443)
            return std::nullopt;
        IPv4 src{},dst{};
        std::copy(p+12,p+16,src.begin());
        std::copy(p+16,p+20,dst.begin());
        // A nonzero IPv4 UDP checksum is required to validate correctly.
        if(be16(u+6)&&udp_checksum(src,dst,u,len)!=0)return std::nullopt;
        sweep(now);
        const auto src_port=be16(u),dst_port=be16(u+2);
        auto it=std::find_if(flows_.begin(),flows_.end(),[&](const Flow& f){
            return f.source==src&&f.destination==dst&&
                f.source_port==src_port&&f.destination_port==dst_port;
        });
        if(it==flows_.end()) {
            if(flows_.size()>=max_flows_||next_id_==0)return std::nullopt;
            flows_.push_back(Flow{next_id_++,src,dst,src_port,dst_port,now});
            it=std::prev(flows_.end());
        } else it->last=now;
        Outbound out;
        out.flow_id=it->id;
        out.destination=dst;
        out.destination_port=dst_port;
        out.socks_destination={1,dst[0],dst[1],dst[2],dst[3],u[2],u[3]};
        out.payload.assign(u+8,u+len);
        return out;
    }
    // Returns an IP/UDP response only for an existing live, matching flow.
    // remote_address/port MUST come from the authenticated proxy response.
    std::optional<std::vector<uint8_t>> response(uint64_t flow_id,
             const IPv4& remote_address,uint16_t remote_port,
             const uint8_t* payload,size_t payload_size,
             Clock::time_point now=Clock::now()) {
        if(!payload&&payload_size)return std::nullopt;
        if(payload_size>65507)return std::nullopt;
        sweep(now);
        auto it=std::find_if(flows_.begin(),flows_.end(),[&](const Flow& f){return f.id==flow_id;});
        if(it==flows_.end()||it->destination!=remote_address||it->destination_port!=remote_port)
            return std::nullopt;
        it->last=now;
        const size_t length=28+payload_size;
        std::vector<uint8_t> packet(length,0);
        packet[0]=0x45;packet[8]=64;packet[9]=17;
        put16(packet.data()+2,uint16_t(length));
        put16(packet.data()+4,next_packet_id_++);
        // Do not fragment responses; oversize replies were rejected above.
        put16(packet.data()+6,0x4000);
        std::copy(it->destination.begin(),it->destination.end(),packet.begin()+12);
        std::copy(it->source.begin(),it->source.end(),packet.begin()+16);
        put16(packet.data()+10,checksum(packet.data(),20));
        uint8_t* u=packet.data()+20;
        put16(u,it->destination_port);put16(u+2,it->source_port);
        put16(u+4,uint16_t(payload_size+8));
        if(payload_size)std::copy(payload,payload+payload_size,packet.begin()+28);
        uint16_t sum=udp_checksum(it->destination,it->source,u,payload_size+8);
        if(sum==0)sum=0xffffu;
        put16(u+6,sum);
        return packet;
    }
    void clear() noexcept {flows_.clear();}
};
} // namespace tun_udp
} // namespace vpn
