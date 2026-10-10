// Test-only loopback packet gateway. No adapter, routes, DNS settings or WFP.
#include "../src/netstack-core.hpp"
#include "../src/native-tun-bootstrap.hpp"
#include <iostream>
using namespace vpn;
namespace {
struct Context { std::map<std::string,std::vector<std::string>> addresses; };
int protect(int64_t,void*) { return 1; }
int resolve(const char* host,char* out,int capacity,void* user) {
    const auto& addresses=static_cast<Context*>(user)->addresses;
    auto found=addresses.find(host);if(found==addresses.end())return -1;
    std::string value;for(const auto& address:found->second)value+=address+'\n';
    if(value.size()>=size_t(capacity))return -1;
    std::memcpy(out,value.data(),value.size());return int(value.size());
}
}
int main(int argc,char** argv) {
    try {
        if(argc!=3||std::string(argv[1])!="--config")throw Failure("arguments","TEST_ARGUMENT");
        NetworkRuntime runtime;stopping=false;auto config=read_config(argv[2]);require_supported(config);
        Context context;
        for(const auto& target:native_bootstrap_targets(config))
            if(!context.addresses.count(target.host))context.addresses.emplace(target.host,node_addresses(target.host,Clock::now()+std::chrono::milliseconds(config.connect_ms)));
        configure_network_hooks({protect,resolve,&context});
        Socket local(::socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP));
        sockaddr_in address{};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        if(bind(local.get(),reinterpret_cast<sockaddr*>(&address),sizeof(address)))throw Failure("bind","TEST_BIND",uint32_t(socket_error()));
        SockLen size=sizeof(address);
        if(getsockname(local.get(),reinterpret_cast<sockaddr*>(&address),&size))throw Failure("address","TEST_BIND");
        nonblocking(local.get());bool pinned=false;sockaddr_in peer{};
        std::cout<<"{\"event\":\"packet_gateway_ready\",\"port\":"<<ntohs(address.sin_port)<<"}"<<std::endl;
        {
            NetstackPackets packets;NetstackCoreBridge bridge(config,packets,64,[](const FlowFailure& failure){
                Json event=Json::obj();event["event"]=Json("flow_failure");event["flow_id"]=Json::integer(failure.id);
                event["reason_code"]=Json(failure.reason);event["phase"]=Json(failure.phase);
                event["flow_protocol"]=Json(failure.protocol==6?"TCP":"UDP");
                event["destination_family"]=Json(failure.address_size==4?"IPv4":"IPv6");
                event["destination_port"]=Json::integer(failure.port);event["native_status"]=Json::integer(failure.native_status);
                std::cout<<json_dump(event)<<std::endl;
            });
            const auto deadline=Clock::now()+std::chrono::minutes(5);
            while(Clock::now()<deadline&&!stopping) {
                bool progress=false;
                for(unsigned i=0;i<32;++i) {
                    uint8_t data[65535];sockaddr_in source{};size=sizeof(source);
                    int n=::recvfrom(local.get(),reinterpret_cast<char*>(data),sizeof(data),0,reinterpret_cast<sockaddr*>(&source),&size);
                    if(n<0){if(would_block(socket_error()))break;throw Failure("receive","TEST_RECEIVE",uint32_t(socket_error()));}
                    if(source.sin_addr.s_addr!=htonl(INADDR_LOOPBACK)||(pinned&&(source.sin_port!=peer.sin_port)))continue;
                    if(!pinned){peer=source;pinned=true;}
                    if(n==4&&std::memcmp(data,"STOP",4)==0){stopping=true;break;}
                    packets.inject(data,size_t(n));progress=true;
                }
                if(progress)bridge.notify_packets();
                if(stopping)break;
                bridge.poll();Bytes packet;
                for(unsigned i=0;i<64&&packets.packet(packet);++i) {
                    int n=::sendto(local.get(),reinterpret_cast<const char*>(packet.data()),int(packet.size()),0,reinterpret_cast<sockaddr*>(&peer),sizeof(peer));
                    if(n!=int(packet.size()))throw Failure("send","TEST_SEND",uint32_t(socket_error()));progress=true;
                }
                if(!progress)std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            stopping=true;bridge.stop();
            std::cout<<json_dump(bridge.metrics())<<std::endl;
        }
        configure_network_hooks({});return 0;
    }catch(const std::exception& error) {
        stopping=true;auto failure=dynamic_cast<const Failure*>(&error);
        Json result=Json::obj();result["event"]=Json("gateway_failure");result["reason_code"]=Json(failure?failure->code:"TEST_FAILURE");result["native_status"]=Json::integer(failure?failure->native_status:0);
        std::cout<<json_dump(result)<<std::endl;return 1;
    }
}
