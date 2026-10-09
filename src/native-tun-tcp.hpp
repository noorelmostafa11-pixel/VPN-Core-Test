// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
// Experimental IPv4 TCP framing and bounded handshake state machine.
// No sockets or OS routes. Not a production TCP/IP stack.
#pragma once
#include <cstddef>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

namespace vpn { namespace tun_tcp {
using IPv4 = std::array<uint8_t,4>;
inline uint16_t be16(const uint8_t* p) noexcept {return uint16_t(uint16_t(p[0])<<8|p[1]);}
inline void put16(uint8_t* p,uint16_t n) noexcept {p[0]=uint8_t(n>>8);p[1]=uint8_t(n);}
inline uint32_t add_words(uint32_t sum,const uint8_t* p,size_t n) noexcept {
    for(size_t i=0;i+1<n;i+=2)sum+=be16(p+i);
    if(n&1)sum+=uint32_t(p[n-1])<<8;
    return sum;
}
inline uint16_t finalize_checksum(uint32_t sum) noexcept {
    while(sum>>16)sum=(sum&0xffffu)+(sum>>16);
    return uint16_t(~sum);
}
inline uint16_t checksum(const uint8_t* p,size_t n) noexcept {return finalize_checksum(add_words(0,p,n));}
using Clock = std::chrono::steady_clock;
inline uint32_t get32(const uint8_t* p) noexcept {
    return uint32_t(p[0])<<24|uint32_t(p[1])<<16|uint32_t(p[2])<<8|p[3];
}
inline void put32(uint8_t* p,uint32_t x) noexcept {
    p[0]=uint8_t(x>>24);p[1]=uint8_t(x>>16);p[2]=uint8_t(x>>8);p[3]=uint8_t(x);
}
inline uint16_t tcp_sum(IPv4 src,IPv4 dst,const uint8_t* tcp,size_t n) noexcept {
    uint32_t s=0;
    s=add_words(s,src.data(),4);
    s=add_words(s,dst.data(),4);
    s+=6u+uint32_t(n);
    return finalize_checksum(add_words(s,tcp,n));
}
struct Key {
    IPv4 src{},dst{};
    uint16_t source_port=0,destination_port=0;
    bool operator<(const Key& other)const noexcept {
        if(src!=other.src)return src<other.src;
        if(dst!=other.dst)return dst<other.dst;
        if(source_port!=other.source_port)return source_port<other.source_port;
        return destination_port<other.destination_port;
    }
};
struct Parsed {
    Key key;
    uint32_t seq=0,ack=0;
    uint16_t window=0;
    uint8_t flags=0;
    std::vector<uint8_t> payload;
};
inline std::optional<Parsed> parse(const uint8_t* p,size_t n) {
    if(!p||n<40||n>65535||p[0]>>4!=4)return std::nullopt;
    const auto ihl=size_t(p[0]&15)*4;
    if(ihl<20||ihl>60||n<ihl+20||be16(p+2)!=n||p[9]!=6||!p[8]||
       (be16(p+6)&0x3fff)!=0||checksum(p,ihl)!=0)return std::nullopt;
    const auto* t=p+ihl;
    const auto tcp_length=n-ihl;
    const auto thl=size_t(t[12]>>4)*4;
    if(thl<20||thl>60||tcp_length<thl||be16(t)==0||be16(t+2)==0)
        return std::nullopt;
    Parsed v;
    std::copy(p+12,p+16,v.key.src.begin());
    std::copy(p+16,p+20,v.key.dst.begin());
    if(tcp_sum(v.key.src,v.key.dst,t,tcp_length)!=0)return std::nullopt;
    v.key.source_port=be16(t);
    v.key.destination_port=be16(t+2);
    v.seq=get32(t+4);v.ack=get32(t+8);v.window=be16(t+14);
    v.flags=t[13];
    if((v.flags&0x20)!=0)return std::nullopt; // urgent data unsupported
    v.payload.assign(t+thl,t+tcp_length);
    return v;
}
inline std::vector<uint8_t> frame(const Key& key,uint32_t seq,uint32_t ack,
                                  uint8_t flags,uint16_t window,
                                  const uint8_t* payload,size_t length,uint16_t packet_id=0) {
    if(length>1200||(!payload&&length))return {};
    std::vector<uint8_t> p(40+length,0);
    p[0]=0x45;p[8]=64;p[9]=6;
    put16(p.data()+2,uint16_t(p.size()));
    put16(p.data()+4,packet_id);
    put16(p.data()+6,0x4000);
    std::copy(key.dst.begin(),key.dst.end(),p.begin()+12);
    std::copy(key.src.begin(),key.src.end(),p.begin()+16);
    put16(p.data()+10,checksum(p.data(),20));
    auto* t=p.data()+20;
    put16(t,key.destination_port);
    put16(t+2,key.source_port);
    put32(t+4,seq);put32(t+8,ack);
    t[12]=0x50;t[13]=flags;
    put16(t+14,window);
    if(length)std::copy(payload,payload+length,p.begin()+40);
    auto check=tcp_sum(key.dst,key.src,t,20+length);
    put16(t+16,check);
    return p;
}
struct Event {
    enum class Kind { opened, bytes, peer_finished, reset } kind;
    Key key;
    std::vector<uint8_t> payload;
};
struct Result {
    std::vector<std::vector<uint8_t>> to_tun;
    std::vector<Event> events;
};
class Handshakes {
    enum class Phase { syn_received, established };
    struct Session {
        Phase phase=Phase::syn_received;
        uint32_t client_next=0,server_next=0;
        Clock::time_point last{};
    };
    std::map<Key,Session> sessions_;
    uint32_t next_initial_=0x4a91a703u;
    uint16_t next_packet_id_=1;
    static constexpr size_t max_sessions_=128;
    static constexpr auto timeout_=std::chrono::seconds(30);
    void sweep(Clock::time_point now) {
        for(auto it=sessions_.begin();it!=sessions_.end();) {
            if(now-it->second.last>=timeout_)it=sessions_.erase(it);
            else ++it;
        }
    }
public:
    size_t size()const noexcept{return sessions_.size();}
    void clear() noexcept {sessions_.clear();}
    Result accept(const uint8_t* p,size_t n,Clock::time_point now=Clock::now()) {
        Result out;
        auto parsed=parse(p,n);
        if(!parsed)return out;
        sweep(now);
        const auto& v=*parsed;
        auto it=sessions_.find(v.key);
        const bool syn=(v.flags&0x02)!=0,ack=(v.flags&0x10)!=0;
        const bool fin=(v.flags&0x01)!=0,rst=(v.flags&0x04)!=0;
        if(it==sessions_.end()) {
            if(!syn||ack||fin||rst||!v.payload.empty()||sessions_.size()>=max_sessions_)return out;
            const uint32_t server_isn=next_initial_;
            next_initial_+=0x100009u;
            Session session;
            session.client_next=v.seq+1;
            session.server_next=server_isn+1;
            session.last=now;
            sessions_.emplace(v.key,session);
            out.to_tun.push_back(frame(v.key,server_isn,session.client_next,0x12,8192,nullptr,0,next_packet_id_++));
            return out;
        }
        Session& session=it->second;
        session.last=now;
        if(rst) {out.events.push_back({Event::Kind::reset,v.key,{}});sessions_.erase(it);return out;}
        if(session.phase==Phase::syn_received) {
            if(syn&&!ack&&v.seq+1==session.client_next) {
                out.to_tun.push_back(frame(v.key,session.server_next-1,session.client_next,0x12,8192,nullptr,0,next_packet_id_++));
                return out;
            }
            if(!ack||syn||fin||v.ack!=session.server_next||v.seq!=session.client_next||!v.payload.empty())return out;
            session.phase=Phase::established;
            out.events.push_back({Event::Kind::opened,v.key,{}});
            return out;
        }
        // No out-of-order acceptance. Application bridge must implement a
        // bounded transmit window, ACK tracking, retransmission, FIN and RST.
        if(!ack||syn||v.ack!=session.server_next||v.seq!=session.client_next)return out;
        if(!v.payload.empty()) {
            if(v.payload.size()>1200)return out;
            session.client_next+=uint32_t(v.payload.size());
            out.events.push_back({Event::Kind::bytes,v.key,v.payload});
            out.to_tun.push_back(frame(v.key,session.server_next,session.client_next,0x10,8192,nullptr,0,next_packet_id_++));
        }
        if(fin) {
            ++session.client_next;
            out.events.push_back({Event::Kind::peer_finished,v.key,{}});
            out.to_tun.push_back(frame(v.key,session.server_next,session.client_next,0x10,0,nullptr,0,next_packet_id_++));
            sessions_.erase(it);
        }
        return out;
    }
};
} } // namespace vpn::tun_tcp
