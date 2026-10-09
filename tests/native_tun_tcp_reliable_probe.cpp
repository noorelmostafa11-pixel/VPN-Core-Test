// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
#include "../src/native-tun-tcp-reliable.hpp"
#include <array>
#include <cassert>
#include <iostream>
#include <vector>
using namespace vpn::tun_tcp;

static std::vector<uint8_t> incoming(const Key& key,uint32_t seq,uint32_t ack,
                                     uint8_t flags,uint16_t window=4096,
                                     const std::vector<uint8_t>& payload={}) {
    Key rev=key;
    std::swap(rev.src,rev.dst);
    std::swap(rev.source_port,rev.destination_port);
    return frame(rev,seq,ack,flags,window,payload.data(),payload.size());
}
int main() {
    const auto t=Clock::now();
    Key key{{198,18,0,2},{1,1,1,1},34345,443};
    Reliable tcp;
    auto syn=incoming(key,1000,0,0x02);
    auto result=tcp.receive(syn.data(),syn.size(),t);
    assert(result.to_tun.size()==1&&tcp.size()==1);
    auto synack=parse(result.to_tun[0].data(),result.to_tun[0].size());
    assert(synack&&synack->flags==0x12&&synack->ack==1001);
    auto initial=synack->seq;
    auto retry=tcp.tick(t+std::chrono::milliseconds(350));
    assert(retry.to_tun.size()==1&&retry.to_tun[0]==result.to_tun[0]);
    auto ack=incoming(key,1001,initial+1,0x10);
    result=tcp.receive(ack.data(),ack.size(),t+std::chrono::milliseconds(400));
    assert(result.events.size()==1&&result.events[0].kind==Event::Kind::opened);
    assert(tcp.tick(t+std::chrono::seconds(2)).to_tun.empty());
    const std::array<uint8_t,3> payload{'x','y','z'};
    auto wire=tcp.send(key,payload.data(),payload.size(),t+std::chrono::seconds(2));
    assert(wire);
    auto decoded=parse(wire->data(),wire->size());
    assert(decoded&&decoded->seq==initial+1&&decoded->ack==1001);
    assert(decoded->payload==std::vector<uint8_t>(payload.begin(),payload.end()));
    assert(!tcp.send(key,payload.data(),payload.size(),t+std::chrono::seconds(2)));
    retry=tcp.tick(t+std::chrono::milliseconds(2400));
    assert(retry.to_tun.size()==1&&retry.to_tun[0]==*wire);
    // The peer ACK must advance the sender's unacknowledged pointer.
    ack=incoming(key,1001,initial+4,0x10);
    result=tcp.receive(ack.data(),ack.size(),t+std::chrono::milliseconds(2450));
    assert(result.events.empty());
    assert(tcp.send(key,payload.data(),payload.size(),t+std::chrono::milliseconds(2500)));
    // ACK the second segment and then receive client data once.
    ack=incoming(key,1001,initial+7,0x10);
    result=tcp.receive(ack.data(),ack.size(),t+std::chrono::milliseconds(2600));
    auto client=incoming(key,1001,initial+7,0x18,4096,{'h','i'});
    result=tcp.receive(client.data(),client.size(),t+std::chrono::milliseconds(2700));
    assert(result.events.size()==1&&result.events[0].kind==Event::Kind::bytes);
    assert(result.events[0].payload==std::vector<uint8_t>({'h','i'}));
    assert(result.to_tun.size()==1);
    assert(parse(result.to_tun[0].data(),result.to_tun[0].size())->ack==1003);
    result=tcp.receive(client.data(),client.size(),t+std::chrono::milliseconds(2800));
    assert(result.events.empty()); // duplicate did not deliver twice
    auto wrong_ack=incoming(key,1003,initial+100,0x10);
    result=tcp.receive(wrong_ack.data(),wrong_ack.size(),t+std::chrono::milliseconds(2900));
    assert(result.events.empty());
    auto peer_fin=incoming(key,1003,initial+7,0x11);
    result=tcp.receive(peer_fin.data(),peer_fin.size(),t+std::chrono::seconds(3));
    assert(result.events.size()==1&&result.events[0].kind==Event::Kind::peer_finished);
    assert(tcp.size()==1); // half-close, can still send server data
    assert(tcp.send(key,payload.data(),payload.size(),t+std::chrono::milliseconds(3100)));
    ack=incoming(key,1004,initial+10,0x10);
    result=tcp.receive(ack.data(),ack.size(),t+std::chrono::milliseconds(3200));
    auto fin=tcp.finish(key,t+std::chrono::milliseconds(3300));
    assert(fin&&parse(fin->data(),fin->size())->flags==0x11);
    ack=incoming(key,1004,initial+11,0x10);
    result=tcp.receive(ack.data(),ack.size(),t+std::chrono::milliseconds(3500));
    assert(tcp.size()==0);
    // Failed SYN handshakes are bounded and torn down after retransmission.
    Key other=key;other.source_port=34346;
    syn=incoming(other,2000,0,0x02);
    result=tcp.receive(syn.data(),syn.size(),t);
    assert(tcp.size()==1);
    std::chrono::milliseconds elapsed{0};
    for(unsigned n=0;n<=5;++n) {
        elapsed+=std::chrono::milliseconds(300u<<n);
        result=tcp.tick(t+elapsed);
    }
    assert(tcp.size()==0);
    // Same flow can be used again after cleanup and isn't stale.
    result=tcp.receive(syn.data(),syn.size(),t+elapsed+std::chrono::milliseconds(1));
    assert(result.to_tun.size()==1);
    auto rst=incoming(other,2001,0,0x04);
    result=tcp.receive(rst.data(),rst.size(),t+elapsed+std::chrono::milliseconds(2));
    assert(result.events.size()==1&&result.events[0].kind==Event::Kind::reset);
    assert(tcp.size()==0);
    std::cout<<"PASS: native TCP retransmission, ACK, in-order data, duplicate suppression, half-close, timeout, RST\n";
}
