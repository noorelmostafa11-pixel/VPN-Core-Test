// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
#include "../src/native-tun-udp.hpp"
#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

using namespace vpn::tun_udp;
static void check(bool valid,const char* reason) {
    if(!valid)throw std::runtime_error(reason);
}
static std::vector<uint8_t> request(uint16_t port,uint16_t source_port=12345) {
    const IPv4 src{198,18,0,2},dst{1,1,1,1};
    std::vector<uint8_t> p(32,0);
    p[0]=0x45;p[8]=64;p[9]=17;
    put16(p.data()+2,uint16_t(p.size()));
    std::copy(src.begin(),src.end(),p.begin()+12);
    std::copy(dst.begin(),dst.end(),p.begin()+16);
    put16(p.data()+10,checksum(p.data(),20));
    put16(p.data()+20,source_port);put16(p.data()+22,port);
    put16(p.data()+24,12);
    p[28]='p';p[29]='i';p[30]='n';p[31]='g';
    put16(p.data()+26,udp_checksum(src,dst,p.data()+20,12));
    return p;
}
int main() {
    const auto zero=Clock::now();
    Flows mapper;
    auto valid=request(53);
    auto outbound=mapper.accept(valid.data(),valid.size(),zero);
    check(outbound.has_value(),"valid UDP rejected");
    check(outbound->destination==IPv4{1,1,1,1},"destination mismatch");
    check(outbound->socks_destination==std::vector<uint8_t>({1,1,1,1,1,0,53}),"SOCKS destination mismatch");
    check(outbound->payload==std::vector<uint8_t>({'p','i','n','g'}),"payload mismatch");
    check(mapper.size()==1,"flow not created");
    const uint64_t id=outbound->flow_id;
    check(mapper.accept(valid.data(),valid.size(),zero)->flow_id==id,"duplicate flow created");
    auto spoof=mapper.response(id,IPv4{8,8,8,8},53,nullptr,0,zero);
    check(!spoof,"unexpected source accepted");
    spoof=mapper.response(id,IPv4{1,1,1,1},443,nullptr,0,zero);
    check(!spoof,"unexpected remote port accepted");
    const std::array<uint8_t,4> answer{'p','o','n','g'};
    auto reply=mapper.response(id,IPv4{1,1,1,1},53,answer.data(),answer.size(),zero);
    check(reply.has_value(),"valid response rejected");
    check(reply->size()==32,"response size mismatch");
    check(checksum(reply->data(),20)==0,"bad IPv4 reply checksum");
    check(udp_checksum(IPv4{1,1,1,1},IPv4{198,18,0,2},reply->data()+20,12)==0,"bad UDP reply checksum");
    check(be16(reply->data()+20)==53&&be16(reply->data()+22)==12345,"ports reversed incorrectly");
    check(std::equal(answer.begin(),answer.end(),reply->begin()+28),"reply payload mismatch");
    check(!mapper.accept(nullptr,0,zero),"null frame accepted");
    auto bad=request(443);check(!mapper.accept(bad.data(),bad.size(),zero),"QUIC not blocked");
    bad=request(53);bad[12]^=1;check(!mapper.accept(bad.data(),bad.size(),zero),"IPv4 checksum not enforced");
    bad=request(53);bad[30]^=1;check(!mapper.accept(bad.data(),bad.size(),zero),"UDP checksum not enforced");
    bad=request(53);bad[6]=0x20;check(!mapper.accept(bad.data(),bad.size(),zero),"fragment accepted");
    bad=request(53);bad[0]=0x60;check(!mapper.accept(bad.data(),bad.size(),zero),"IPv6 accepted");
    bad=request(53);bad[25]=11;check(!mapper.accept(bad.data(),bad.size(),zero),"bad UDP length accepted");
    bad=request(53);bad[8]=0;check(!mapper.accept(bad.data(),bad.size(),zero),"zero TTL accepted");
    // 256 flows maximum; 257th must be rejected rather than evicting a live flow.
    for(unsigned i=1;i<256;i++) {
        auto p=request(53,uint16_t(12345+i));
        check(mapper.accept(p.data(),p.size(),zero).has_value(),"flow capacity too small");
    }
    auto full=request(53,40000);
    check(!mapper.accept(full.data(),full.size(),zero),"unbounded flow table");
    check(mapper.size()==256,"wrong table size");
    // Aged flows are removed, and late responses must not recreate a flow.
    check(!mapper.response(id,IPv4{1,1,1,1},53,answer.data(),answer.size(),zero+std::chrono::seconds(61)),"expired flow accepted");
    check(mapper.size()==0,"expired flows retained");
    check(mapper.accept(full.data(),full.size(),zero+std::chrono::seconds(61)).has_value(),"flow table did not recover");
    mapper.clear();check(mapper.size()==0,"clear failed");
    std::cout<<"PASS: native TUN UDP encapsulation, checksum, flow isolation, bounds and expiry\n";
}
