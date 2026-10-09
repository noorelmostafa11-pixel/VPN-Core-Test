// Verify asynchronous UDP denial by an exact app-owned WFP filter.
// Disposable CI diagnostic only. Restore the prior global event collection option.
#include "../src/base.hpp"
#include "../src/native-windows-policy.hpp"
#include <iostream>
#include <thread>
using namespace vpn;
int main(int argc,char** argv){
    HANDLE engine=nullptr;FWP_VALUE0* prior=nullptr;
    try{
        if(argc!=2)throw std::runtime_error("physical interface required");
        WSADATA data{};if(WSAStartup(MAKEWORD(2,2),&data))throw std::runtime_error("Winsock startup");
        struct WsaCleanup{~WsaCleanup(){WSACleanup();}} network;
        auto check=[](DWORD code){if(code)throw std::runtime_error("WFP probe status "+std::to_string(code));};
        check(FwpmEngineOpen0(nullptr,RPC_C_AUTHN_WINNT,nullptr,nullptr,&engine));
        check(FwpmEngineGetOption0(engine,FWPM_ENGINE_COLLECT_NET_EVENTS,&prior));
        FWP_VALUE0 enabled{};enabled.type=FWP_UINT32;enabled.uint32=1;check(FwpmEngineSetOption0(engine,FWPM_ENGINE_COLLECT_NET_EVENTS,&enabled));
        FILETIME start{};GetSystemTimeAsFileTime(&start);
        SOCKET raw=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);if(raw==INVALID_SOCKET)throw std::runtime_error("probe socket");
        struct CloseSocket{SOCKET s;~CloseSocket(){closesocket(s);}} close_socket{raw};
        DWORD index=htonl(ULONG(std::stoul(argv[1])));
        if(setsockopt(raw,IPPROTO_IP,IP_UNICAST_IF,reinterpret_cast<const char*>(&index),sizeof(index)))throw std::runtime_error("probe uplink");
        sockaddr_in target{};target.sin_family=AF_INET;target.sin_port=htons(53);InetPtonA(AF_INET,"1.1.1.1",&target.sin_addr);
        const char payload[]="vpn-core-owned-WFP-UDP-drop-fixture";
        sendto(raw,payload,sizeof(payload),0,reinterpret_cast<sockaddr*>(&target),sizeof(target));
        bool found=false;auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);uint64_t filter_id=0;
        while(!found&&std::chrono::steady_clock::now()<deadline){
            std::this_thread::sleep_for(std::chrono::milliseconds(100));FWPM_NET_EVENT_ENUM_TEMPLATE0 query{};query.startTime=start;GetSystemTimeAsFileTime(&query.endTime);HANDLE enumeration=nullptr;check(FwpmNetEventCreateEnumHandle0(engine,&query,&enumeration));
            struct CloseEnum{HANDLE e,h;~CloseEnum(){FwpmNetEventDestroyEnumHandle0(e,h);}} close_enum{engine,enumeration};
            for(;;){FWPM_NET_EVENT0** events=nullptr;UINT32 count=0;check(FwpmNetEventEnum0(engine,enumeration,256,&events,&count));
                for(UINT32 i=0;i<count;++i){auto* e=events[i];if(e->type!=FWPM_NET_EVENT_TYPE_CLASSIFY_DROP||e->header.ipProtocol!=IPPROTO_UDP||e->header.remotePort!=53||e->header.ipVersion!=FWP_IP_VERSION_V4||e->header.remoteAddrV4!=0x01010101u)continue;
                    FWPM_FILTER0* filter=nullptr;if(FwpmFilterGetById0(engine,e->classifyDrop->filterId,&filter)==0){if(filter->providerKey&&IsEqualGUID(*filter->providerKey,tun_policy_owner)){found=true;filter_id=e->classifyDrop->filterId;}FwpmFreeMemory0(reinterpret_cast<void**>(&filter));}
                }
                FwpmFreeMemory0(reinterpret_cast<void**>(&events));if(count<256)break;
            }
        }
        check(FwpmEngineSetOption0(engine,FWPM_ENGINE_COLLECT_NET_EVENTS,prior));FwpmFreeMemory0(reinterpret_cast<void**>(&prior));FwpmEngineClose0(engine);engine=nullptr;
        if(!found)throw std::runtime_error("No owned WFP UDP DNS drop recorded");
        std::cout<<"PASS: owned WFP UDP DNS classify-drop filter="<<filter_id<<"\n";return 0;
    }catch(const std::exception& e){if(engine){if(prior)FwpmEngineSetOption0(engine,FWPM_ENGINE_COLLECT_NET_EVENTS,prior);FwpmEngineClose0(engine);}if(prior)FwpmFreeMemory0(reinterpret_cast<void**>(&prior));std::cerr<<e.what()<<"\n";return 1;}
}
