#define VPN_CORE_SCHANNEL_TEST
#include "../src/tls.hpp"
#include <iostream>
#include <thread>
vpn::Bytes record(char type,const std::string& data){vpn::Bytes out{uint8_t(type),uint8_t(data.size()>>8),uint8_t(data.size())};out.insert(out.end(),data.begin(),data.end());return out;}
void check(bool value,const char* name){if(!value)throw std::runtime_error(name);}
int main(){try{
    for(char type:{'R','E','N'}){
        vpn::Config c;c.server="127.0.0.1";c.tls_name="localhost";auto listener=vpn::listen_local(0);sockaddr_in address{};socklen_t len=sizeof(address);getsockname(listener.get(),reinterpret_cast<sockaddr*>(&address),&len);c.port=ntohs(address.sin_port);auto deadline=vpn::Clock::now()+std::chrono::seconds(5);
        std::thread peer([&]{vpn::wait_socket(listener.get(),false,deadline);vpn::Socket socket(accept(listener.get(),nullptr,nullptr));auto hello=vpn::receive_exact(socket,1,deadline);check(hello==vpn::to_bytes("H"),"client hello");auto finish=vpn::to_bytes("F");vpn::send_all(socket,finish.data(),finish.size(),deadline);});
        auto socket=vpn::connect_server(c,deadline);vpn::Tls tls;tls.handshake(socket,c,deadline);peer.join();
        auto ticket=record(type,"tic"),app=record('D',"response");
        if(type!='N')ticket.insert(ticket.end(),app.begin(),app.end());
        auto plain=tls.feed(ticket.data(),ticket.size());check(!tls.negotiating(),"ticket context remains pending");check(tls.take_control()==vpn::to_bytes("K"),"ticket control token");if(type=='N')plain=tls.feed(app.data(),app.size());check(plain==vpn::to_bytes("response"),"extra bytes lost");
        auto start=record(type,"mor");check(tls.feed(start.data(),start.size()).empty(),"control exposed as data");check(tls.negotiating(),"continuation not pending");check(tls.take_control()==vpn::to_bytes("A"),"continuation token");auto count=fake_encrypt_calls;check(tls.encrypt(vpn::to_bytes("deferred")).empty(),"pending context encrypted data");check(fake_encrypt_calls==count,"Encrypt called while pending");check(tls.pending_bytes()==8,"pending application data accounting");auto end=vpn::to_bytes("fin");check(tls.feed(end.data(),1).empty(),"partial context input");check(tls.negotiating(),"partial input completed context");tls.feed(end.data()+1,2);check(!tls.negotiating(),"context not completed");auto control=tls.take_control();auto expected=vpn::to_bytes("B");auto encrypted=record('D',"deferred");expected.insert(expected.end(),encrypted.begin(),encrypted.end());check(control==expected,"control/application ordering");
        auto failure=record(type,"bad");bool rejected=false;try{tls.feed(failure.data(),failure.size());}catch(const vpn::Failure& f){rejected=f.code=="TLS_CERTIFICATE_UNTRUSTED"&&f.native_status==0x80090325u;}check(rejected,"post-handshake verification error ignored");
    }
    for(auto choice:std::vector<std::pair<ULONG,ULONG>>{{SP_PROT_TLS1_2,0xc02f},{SP_PROT_TLS1_2,0x002f},{SP_PROT_TLS1_0,0x1301}}){
        fake_tls_protocol=choice.first;fake_tls_cipher=choice.second;
        vpn::Config c;c.server="127.0.0.1";c.tls_name="localhost";auto listener=vpn::listen_local(0);sockaddr_in address{};socklen_t len=sizeof(address);getsockname(listener.get(),reinterpret_cast<sockaddr*>(&address),&len);c.port=ntohs(address.sin_port);auto deadline=vpn::Clock::now()+std::chrono::seconds(5);
        std::thread peer([&]{vpn::wait_socket(listener.get(),false,deadline);vpn::Socket socket(accept(listener.get(),nullptr,nullptr));(void)vpn::receive_exact(socket,1,deadline);auto finish=vpn::to_bytes("F");vpn::send_all(socket,finish.data(),finish.size(),deadline);});
        auto socket=vpn::connect_server(c,deadline);vpn::Tls tls;bool rejected=false;try{tls.handshake(socket,c,deadline);}catch(const vpn::Failure& f){rejected=f.code=="TLS_SECURITY_POLICY";}peer.join();check(rejected==(choice.second!=0xc02f),"TLS version/cipher policy");
    }
    std::cout<<"PASS: Schannel modified token, EXTRA/no EXTRA, coalesced records, partial continuation, deferred encryption, wire ordering, verification rejection, TLS 1.2 AEAD acceptance and CBC/old-version rejection\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
