#pragma once
#include "udp-protocol.hpp"
#include "xhttp-provider.hpp"
#include <functional>
#include <memory>
namespace vpn {
#ifdef _WIN32
using SockLen=int;
#else
using SockLen=socklen_t;
#endif
inline Socket connect_udp_server(const Config& c){
    auto names=node_addresses(c.server,Clock::now()+std::chrono::milliseconds(c.connect_ms));auto port=std::to_string(c.port);
    for(const auto& name:names){addrinfo hints{};hints.ai_socktype=SOCK_DGRAM;hints.ai_family=AF_UNSPEC;
        hints.ai_flags=AI_NUMERICHOST;
        addrinfo* list=nullptr;if(getaddrinfo(name.c_str(),port.c_str(),&hints,&list))continue;
        struct Cleanup{addrinfo* p;~Cleanup(){freeaddrinfo(p);}} cleanup{list};
        for(auto p=list;p;p=p->ai_next){Socket socket(::socket(p->ai_family,SOCK_DGRAM,IPPROTO_UDP));if(socket.get()==invalid_socket)continue;
            auto allowed=protect_socket_callback(int64_t(socket.get()),nullptr);check_cancelled();if(!allowed)throw Failure("CONNECT_FAILED: UDP socket protection rejected","SOCKET_PROTECTION_FAILED");
            if(::connect(socket.get(),p->ai_addr,SockLen(p->ai_addrlen)))continue;nonblocking(socket.get());return socket;}
    }throw Failure("CONNECT_FAILED: UDP node socket failed","UDP_CONNECT_FAILED");
}
class UdpTunnel {
    const Config& config_;Protocol protocol_;UdpStreamCodec codec_;Socket server_;SecureStream tls_;Transport transport_;XHttpStream xhttp_;Queue up_;Bytes pending_;bool provider_;Clock::time_point last_=Clock::now();
    std::vector<Datagram> process(const Bytes& wire){auto out=codec_.decode(protocol_,provider_?wire:transport_.decode(wire));
        auto control=protocol_.take_control();if(!control.empty()){if(provider_)append(pending_,control);else up_.append(tls_.encrypt(transport_.encode(control)));}
        if(!provider_){up_.append(tls_.take_control());auto t=transport_.take_control();if(!t.empty())up_.append(tls_.encrypt(t));}
        if(!out.empty())last_=Clock::now();return out;
    }
public:
    UdpTunnel(const Config& c,const Bytes& destination,size_t maximum_payload=65507):config_(c),protocol_(c,true),codec_(c,destination,maximum_payload),transport_(c),provider_(c.transport=="xhttp"||c.transport=="http"||c.transport=="kcp"||c.transport=="quic"){
        auto deadline=Clock::now()+std::chrono::milliseconds(c.connect_ms);
        if(provider_){xhttp_.open(c,protocol_.open(destination),deadline);return;}
        server_=connect_server(c,deadline);tls_.handshake(server_,c,deadline);Bytes header;
        if(c.transport=="websocket"&&c.ws_early_data)header=transport_.prepare(protocol_.open(destination));
        auto initial=transport_.open(server_,tls_,deadline,header.empty()?nullptr:&header);
        if(c.transport=="websocket"&&c.ws_early_data){if(!header.empty())send_secure(server_,tls_,transport_.encode_prepared(header),deadline);}
        else send_secure(server_,tls_,transport_.encode(protocol_.open(destination)),deadline);
        // No response datagram can precede the first UDP payload.
        if(!initial.empty())process(initial);
    }
    size_t pending_bytes(){return up_.size()+pending_.size()+tls_.pending_bytes()+transport_.pending_bytes()+protocol_.pending_bytes();}
    void send(const Bytes& payload){auto wire=codec_.encode(protocol_,payload);
        if(provider_){if(pending_.size()+wire.size()>524288)throw Failure("RELAY_FAILED: UDP upload buffer","UDP_BUFFER_LIMIT");append(pending_,wire);}
        else up_.append(tls_.encrypt(transport_.encode(wire)));last_=Clock::now();
    }
    std::vector<Datagram> poll(){
        if(Clock::now()-last_>std::chrono::milliseconds(config_.idle_ms))throw Failure("RELAY_FAILED: UDP tunnel idle","UDP_IDLE_TIMEOUT");
        std::vector<Datagram> out;
        if(provider_){out=process(xhttp_.read());if(!pending_.empty()&&xhttp_.write(pending_))pending_.clear();if(xhttp_.closed()||protocol_.closed())throw Failure("RELAY_FAILED: UDP tunnel closed","UDP_TUNNEL_CLOSED");return out;}
        out=process(tls_.feed(nullptr,0));if(!up_.empty())up_.flush(server_);
        for(unsigned i=0;i<16;++i){uint8_t bytes[65536];int n=server_.receive(bytes,sizeof(bytes));if(n==-2)break;if(n==0)throw Failure("RELAY_FAILED: UDP carrier closed","UDP_TUNNEL_CLOSED");
            auto packets=process(tls_.feed(bytes,size_t(n)));out.insert(out.end(),std::make_move_iterator(packets.begin()),std::make_move_iterator(packets.end()));}
        return out;
    }
};
inline void udp_associate(Socket& control,const Config& config,const Bytes& requested,bool& ready,
    std::atomic<bool>& stopping,uint64_t& uploaded,uint64_t& downloaded,
    const std::function<void(const std::string&)>& note){
    Socket local(::socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP));if(local.get()==invalid_socket)throw Failure("SOCKS_FAILED: UDP listener create","UDP_LISTENER_CREATE");
    sockaddr_in bound{};bound.sin_family=AF_INET;bound.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(bind(local.get(),reinterpret_cast<sockaddr*>(&bound),sizeof(bound)))throw Failure("SOCKS_FAILED: UDP listener bind","UDP_LISTENER_BIND");
    SockLen size=sizeof(bound);if(getsockname(local.get(),reinterpret_cast<sockaddr*>(&bound),&size))throw Failure("SOCKS_FAILED: UDP listener address","UDP_LISTENER_ADDRESS");nonblocking(local.get());
    sockaddr_in peer{};size=sizeof(peer);if(getpeername(control.get(),reinterpret_cast<sockaddr*>(&peer),&size))throw Failure("SOCKS_FAILED: UDP control peer","UDP_CONTROL_PEER");
    peer.sin_port=htons(uint16_t(get16(requested,requested.size()-2)));bool pinned=peer.sin_port!=0;
    Bytes reply{5,0,0,1,127,0,0,1};be16(reply,ntohs(bound.sin_port));send_all(control,reply.data(),reply.size(),Clock::now()+std::chrono::milliseconds(config.connect_ms));
    ready=true;
    std::map<std::string,std::unique_ptr<UdpTunnel>> tunnels;std::unique_ptr<ShadowsocksUdp> ss;Socket ss_socket;
    std::map<std::string,Clock::time_point> awaiting;
    auto expect=[&](const Bytes& address){if(config.udp_response_ms){auto key=hex_bytes(address);if(awaiting.size()<64||awaiting.count(key))awaiting.emplace(key,Clock::now()+std::chrono::milliseconds(config.udp_response_ms));}};
    auto report=[&](const std::exception& error){auto f=dynamic_cast<const Failure*>(&error);note(f?f->code:"UDP_RELAY_FAILED");};
    auto return_packet=[&](const Datagram& packet){awaiting.erase(hex_bytes(packet.address));Bytes wire{0,0,0};append(wire,packet.address);append(wire,packet.payload);if(wire.size()>65507)return;
        int n=::sendto(local.get(),reinterpret_cast<const char*>(wire.data()),int(wire.size()),0,reinterpret_cast<sockaddr*>(&peer),sizeof(peer));if(n==int(wire.size()))downloaded+=packet.payload.size();};
    while(!stopping){for(auto it=awaiting.begin();it!=awaiting.end();)if(Clock::now()>=it->second){note("UDP_NO_RESPONSE");it=awaiting.erase(it);}else ++it;fd_set reads;FD_ZERO(&reads);FD_SET(control.get(),&reads);FD_SET(local.get(),&reads);timeval timeout{0,10000};
        auto highest=std::max(control.get(),local.get());int result=select(int(highest+1),&reads,nullptr,nullptr,&timeout);
        if(result<0){
#ifndef _WIN32
            if(errno==EINTR)continue;
#endif
            throw Failure("RELAY_FAILED: UDP association wait","UDP_SOCKET_WAIT");}
        if(FD_ISSET(control.get(),&reads)){uint8_t byte[256];int n=control.receive(byte,sizeof(byte));if(n==0)break;}
        if(FD_ISSET(local.get(),&reads))for(unsigned i=0;i<32;++i){uint8_t bytes[65536];sockaddr_in source{};size=sizeof(source);
            int n=::recvfrom(local.get(),reinterpret_cast<char*>(bytes),sizeof(bytes),0,reinterpret_cast<sockaddr*>(&source),&size);
            if(n<0){if(would_block(socket_error()))break;throw Failure("RELAY_FAILED: UDP client receive","UDP_CLIENT_RECEIVE");}
            if(n<4||source.sin_addr.s_addr!=peer.sin_addr.s_addr||(pinned&&source.sin_port!=peer.sin_port))continue;
            if(bytes[0]!=0||bytes[1]!=0||bytes[2]!=0)continue; // RFC 1928 fragments are dropped.
            try{Bytes body(bytes+3,bytes+n);auto address_size=socks_address_size(body);if(!address_size)continue;
                Datagram packet{consume(body,address_size),std::move(body)};
                if(!pinned){peer.sin_port=source.sin_port;pinned=true;}
                if(config.protocol=="ss"){
                    if(!ss){ss_socket=connect_udp_server(config);ss=std::make_unique<ShadowsocksUdp>(config);}
                    auto wire=ss->encode(packet);int sent=::send(ss_socket.get(),reinterpret_cast<const char*>(wire.data()),int(wire.size()),0);if(sent==int(wire.size())){uploaded+=packet.payload.size();expect(packet.address);}else if(sent<0&&!would_block(socket_error()))throw Failure("RELAY_FAILED: UDP socket send","UDP_SEND_FAILED",uint32_t(socket_error()));
                }else{auto key=hex_bytes(packet.address);auto it=tunnels.find(key);
                    if(it==tunnels.end()){if(tunnels.size()>=std::min(size_t(config.max_connections),size_t(64)))throw Failure("RELAY_FAILED: UDP destination limit","UDP_DESTINATION_LIMIT");it=tunnels.emplace(key,std::make_unique<UdpTunnel>(config,packet.address)).first;}
                    try{it->second->send(packet.payload);}catch(...){tunnels.erase(it);throw;}uploaded+=packet.payload.size();expect(packet.address);}
            }catch(const std::exception& error){report(error);}
        }
        for(auto it=tunnels.begin();it!=tunnels.end();)try{for(const auto& packet:it->second->poll())return_packet(packet);++it;}catch(const std::exception& error){report(error);it=tunnels.erase(it);}
        if(ss)for(unsigned i=0;i<32;++i){uint8_t bytes[65536];int n;try{n=ss_socket.receive(bytes,sizeof(bytes));}catch(const std::exception& error){report(error);break;}if(n==-2)break;if(n<=0)break;
            try{return_packet(ss->decode(Bytes(bytes,bytes+n)));}catch(const std::exception& error){report(error);}}
    }
}
}
