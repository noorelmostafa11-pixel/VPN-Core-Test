// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
// Experimental in-process TCP reliability layer for IPv4 TUN packets.
// No sockets, DNS, routing or proxy forwarding. NOT a production TCP/IP stack.
// Single-worker API. The application must provide bounded backpressure and
// deliver bytes to the encrypted engine before acknowledging production data.
#pragma once
#include "native-tun-tcp.hpp"
#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <random>
#include <utility>
#include <vector>

namespace vpn { namespace tun_tcp {
class Reliable {
    struct Pending {
        std::vector<uint8_t> frame;
        Clock::time_point sent{};
        unsigned retries=0;
        bool fin=false;
    };
    struct State {
        uint32_t receive_next=0,send_next=0,send_una=0;
        uint16_t window=0;
        bool established=false,peer_finished=false,local_fin=false,local_fin_acked=false;
        Clock::time_point last{};
        std::optional<Pending> pending;
    };
    std::map<Key,State> connections_;
    uint16_t packet_id_=1;
    std::mt19937 generator_;
    static constexpr size_t capacity_=128;
    static constexpr size_t max_segment_=536; // No negotiated MSS option.
    static constexpr auto idle_=std::chrono::seconds(120);
    std::vector<uint8_t> emit(const Key& key,uint32_t seq,uint32_t ack,uint8_t flags,
                              const uint8_t* bytes=nullptr,size_t count=0) {
        return frame(key,seq,ack,flags,8192,bytes,count,packet_id_++);
    }
    static bool ack_in_range(uint32_t ack,uint32_t una,uint32_t next) noexcept {
        return int32_t(ack-una)>=0 && int32_t(next-ack)>=0;
    }
public:
    Reliable():generator_(std::random_device{}()){}
    size_t size()const noexcept{return connections_.size();}
    void clear() noexcept {connections_.clear();}
    Result receive(const uint8_t* bytes,size_t size,Clock::time_point now=Clock::now()) {
        Result result;
        auto parsed=parse(bytes,size);
        if(!parsed)return result;
        for(auto it=connections_.begin();it!=connections_.end();) {
            if(now-it->second.last>idle_)it=connections_.erase(it);
            else ++it;
        }
        const Parsed& p=*parsed;
        bool syn=(p.flags&0x02)!=0,ack=(p.flags&0x10)!=0;
        bool rst=(p.flags&0x04)!=0,fin=(p.flags&0x01)!=0;
        auto it=connections_.find(p.key);
        if(it==connections_.end()) {
            if(!syn||ack||rst||fin||!p.payload.empty()||connections_.size()>=capacity_)
                return result;
            uint32_t isn=generator_();
            State state;
            state.receive_next=p.seq+1;
            state.send_una=isn;state.send_next=isn+1;
            state.window=p.window;state.last=now;
            auto response=emit(p.key,isn,state.receive_next,0x12);
            state.pending=Pending{response,now,0,false};
            connections_.emplace(p.key,std::move(state));
            result.to_tun.push_back(std::move(response));
            return result;
        }
        State& state=it->second;
        state.last=now;
        if(rst) {
            result.events.push_back({Event::Kind::reset,p.key,{}});
            connections_.erase(it);
            return result;
        }
        if(!state.established) {
            if(syn&&!ack&&p.seq+1==state.receive_next) {
                result.to_tun.push_back(state.pending->frame);
                return result;
            }
            if(!ack||syn||fin||p.seq!=state.receive_next||p.ack!=state.send_next||
                !p.payload.empty())return result;
            state.send_una=state.send_next;
            state.pending.reset();
            state.established=true;state.window=p.window;
            result.events.push_back({Event::Kind::opened,p.key,{}});
            return result;
        }
        if(!ack||syn||!ack_in_range(p.ack,state.send_una,state.send_next)) {
            result.to_tun.push_back(emit(p.key,state.send_next,state.receive_next,0x10));
            return result;
        }
        state.window=p.window;
        if(p.ack==state.send_next) {
            state.send_una=p.ack;
            if(state.pending) {
                state.local_fin_acked=state.pending->fin;
                state.pending.reset();
            }
        }
        if(p.seq!=state.receive_next) {
            // Out-of-order/duplicate packets are never delivered twice.
            result.to_tun.push_back(emit(p.key,state.send_next,state.receive_next,0x10));
            return result;
        }
        if(state.peer_finished) {
            if(!p.payload.empty()||fin)
                result.to_tun.push_back(emit(p.key,state.send_next,state.receive_next,0x10));
        } else {
            // Limit accepted segment size; the future bridge must implement
            // a bounded receive queue/advertised-window backpressure.
            if(p.payload.size()>1460)return result;
            if(!p.payload.empty()) {
                state.receive_next+=uint32_t(p.payload.size());
                result.events.push_back({Event::Kind::bytes,p.key,p.payload});
                result.to_tun.push_back(emit(p.key,state.send_next,state.receive_next,0x10));
            }
            if(fin) {
                ++state.receive_next;state.peer_finished=true;
                result.events.push_back({Event::Kind::peer_finished,p.key,{}});
                result.to_tun.push_back(emit(p.key,state.send_next,state.receive_next,0x10));
            }
        }
        if(state.peer_finished&&state.local_fin_acked)connections_.erase(it);
        return result;
    }
    // Returns null when remote data cannot be accepted without buffering.
    // Caller MUST retry after ACK. Exactly one outstanding server segment.
    std::optional<std::vector<uint8_t>> send(const Key& key,const uint8_t* data,size_t len,
                                               Clock::time_point now=Clock::now()) {
        auto it=connections_.find(key);
        if(it==connections_.end()||!it->second.established||it->second.local_fin||
           it->second.pending||!data||len==0||len>max_segment_||
           len>it->second.window)return std::nullopt;
        State& state=it->second;
        auto wire=emit(key,state.send_next,state.receive_next,0x18,data,len);
        state.pending=Pending{wire,now,0,false};
        state.send_next+=uint32_t(len);state.last=now;
        return wire;
    }
    // Must be called after encrypted proxy EOF; does not close the peer's
    // transmit direction and does not discard unacknowledged server bytes.
    std::optional<std::vector<uint8_t>> finish(const Key& key,Clock::time_point now=Clock::now()) {
        auto it=connections_.find(key);
        if(it==connections_.end()||!it->second.established||it->second.local_fin||
           it->second.pending)return std::nullopt;
        State& state=it->second;
        auto wire=emit(key,state.send_next,state.receive_next,0x11);
        state.pending=Pending{wire,now,0,true};
        ++state.send_next;state.local_fin=true;state.last=now;
        return wire;
    }
    std::optional<std::vector<uint8_t>> reset(const Key& key) {
        auto it=connections_.find(key);
        if(it==connections_.end())return std::nullopt;
        const auto wire=emit(key,it->second.send_next,it->second.receive_next,0x14);
        connections_.erase(it);
        return wire;
    }
    Result tick(Clock::time_point now=Clock::now()) {
        Result result;
        for(auto it=connections_.begin();it!=connections_.end();) {
            State& state=it->second;
            if(now-state.last>=idle_) {
                result.events.push_back({Event::Kind::reset,it->first,{}});
                it=connections_.erase(it);continue;
            }
            if(state.pending) {
                Pending& pending=*state.pending;
                const auto backoff=std::chrono::milliseconds(300u<<std::min(pending.retries,5u));
                if(now-pending.sent>=backoff) {
                    if(pending.retries>=5) {
                        result.events.push_back({Event::Kind::reset,it->first,{}});
                        it=connections_.erase(it);continue;
                    }
                    result.to_tun.push_back(pending.frame);
                    pending.sent=now;
                    ++pending.retries;
                }
            }
            ++it;
        }
        return result;
    }
};
} } // namespace vpn::tun_tcp
