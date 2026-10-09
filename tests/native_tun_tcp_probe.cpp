// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
#include "../src/native-tun-tcp.hpp"
#include <cassert>
#include <iostream>
using namespace vpn::tun_tcp;
static std::vector<uint8_t> incoming(const Key& key,uint32_t seq,uint32_t ack,uint8_t flags,
                                    const std::vector<uint8_t>& payload={}) {
    auto reversed=key;
    std::swap(reversed.src,reversed.dst);
    std::swap(reversed.source_port,reversed.destination_port);
    return frame(reversed,seq,ack,flags,4096,payload.data(),payload.size());
}
int main() {
    Key k{{198,18,0,2},{1,1,1,1},31234,443};
    Handshakes hs;
    auto syn=incoming(k,1000,0,0x02);
    auto r=hs.accept(syn.data(),syn.size());
    assert(r.to_tun.size()==1&&hs.size()==1);
    auto synack=parse(r.to_tun[0].data(),r.to_tun[0].size());
    assert(synack&&synack->flags==0x12&&synack->ack==1001);
    auto ack=incoming(k,1001,synack->seq+1,0x10);
    r=hs.accept(ack.data(),ack.size());
    assert(r.events.size()==1&&r.events[0].kind==Event::Kind::opened);
    auto bytes=incoming(k,1001,synack->seq+1,0x18,{'h','i'});
    r=hs.accept(bytes.data(),bytes.size());
    assert(r.events.size()==1&&r.events[0].kind==Event::Kind::bytes);
    assert(r.events[0].payload==std::vector<uint8_t>({'h','i'}));
    assert(r.to_tun.size()==1&&parse(r.to_tun[0].data(),r.to_tun[0].size())->ack==1003);
    r=hs.accept(bytes.data(),bytes.size());assert(r.events.empty());
    auto wrong=incoming(k,1003,synack->seq+2,0x18,{'!'});
    r=hs.accept(wrong.data(),wrong.size());assert(r.events.empty());
    auto fin=incoming(k,1003,synack->seq+1,0x11);
    r=hs.accept(fin.data(),fin.size());
    assert(r.events.size()==1&&r.events[0].kind==Event::Kind::peer_finished&&hs.size()==0);
    auto corrupt=syn;corrupt[15]^=0x01;
    r=hs.accept(corrupt.data(),corrupt.size());assert(r.to_tun.empty());
    std::cout<<"PASS: native TCP isolated handshake/sequence/payload/FIN/checksum probe\n";
}
