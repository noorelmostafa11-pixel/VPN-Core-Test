// Full in-process Windows launcher. Uses the existing parser and protocols.
#define VPN_CORE_SHARED
#include "main.cpp"
#include "native-windows-policy.hpp"
#include <iphlpapi.h>
#include <future>
namespace {
using namespace vpn;
struct Context {std::string host;std::vector<std::string> addresses;ULONG uplink=0;};
int protect_node(int64_t handle,void* user){
    auto& context=*static_cast<Context*>(user);WSAPROTOCOL_INFOA info{};int size=sizeof(info);
    if(getsockopt(SOCKET(handle),SOL_SOCKET,SO_PROTOCOL_INFOA,reinterpret_cast<char*>(&info),&size))return 0;
    DWORD index=info.iAddressFamily==AF_INET?htonl(context.uplink):context.uplink;
    return setsockopt(SOCKET(handle),info.iAddressFamily==AF_INET?IPPROTO_IP:IPPROTO_IPV6,info.iAddressFamily==AF_INET?IP_UNICAST_IF:IPV6_UNICAST_IF,reinterpret_cast<const char*>(&index),sizeof(index))==0?1:0;
}
int resolve_node(const char* host,char* output,int capacity,void* user){auto& c=*static_cast<Context*>(user);if(c.host!=host)return -1;std::string s;for(const auto& a:c.addresses)s+=a+'\n';if(s.size()>=size_t(capacity))return -1;std::memcpy(output,s.data(),s.size());return int(s.size());}
BOOL WINAPI console_stop(DWORD reason){if(reason<=CTRL_SHUTDOWN_EVENT){vpn_core_stop();return TRUE;}return FALSE;}
struct OwnedRoutes {
    std::vector<MIB_IPFORWARD_ROW2> routes;
    std::vector<MIB_UNICASTIPADDRESS_ROW> addresses;
    ~OwnedRoutes(){for(auto i=routes.rbegin();i!=routes.rend();++i)DeleteIpForwardEntry2(&*i);for(auto i=addresses.rbegin();i!=addresses.rend();++i)DeleteUnicastIpAddressEntry(&*i);}
    void address(uint64_t luid,const char* text,bool v6,unsigned prefix) {
        MIB_UNICASTIPADDRESS_ROW row{};InitializeUnicastIpAddressEntry(&row);row.InterfaceLuid.Value=luid;row.Address.si_family=v6?AF_INET6:AF_INET;
        if(InetPtonA(v6?AF_INET6:AF_INET,text,v6?static_cast<void*>(&row.Address.Ipv6.sin6_addr):static_cast<void*>(&row.Address.Ipv4.sin_addr))!=1)throw Failure("STARTUP_FAILED: interface IP","TUN_POLICY_ADDRESS");
        row.OnLinkPrefixLength=UINT8(prefix);row.DadState=IpDadStatePreferred;row.PrefixOrigin=IpPrefixOriginManual;row.SuffixOrigin=IpSuffixOriginManual;row.ValidLifetime=0xffffffffu;row.PreferredLifetime=0xffffffffu;
        auto e=CreateUnicastIpAddressEntry(&row);if(e)throw Failure("STARTUP_FAILED: interface address","TUN_ADDRESS",e);addresses.push_back(row);
    }
    void route(uint64_t luid,const char* prefix,bool v6,unsigned length) {
        MIB_IPFORWARD_ROW2 row{};InitializeIpForwardEntry(&row);row.InterfaceLuid.Value=luid;row.DestinationPrefix.Prefix.si_family=v6?AF_INET6:AF_INET;row.NextHop.si_family=v6?AF_INET6:AF_INET;
        InetPtonA(v6?AF_INET6:AF_INET,prefix,v6?static_cast<void*>(&row.DestinationPrefix.Prefix.Ipv6.sin6_addr):static_cast<void*>(&row.DestinationPrefix.Prefix.Ipv4.sin_addr));
        row.DestinationPrefix.PrefixLength=UINT8(length);row.Metric=5;row.Protocol=MIB_IPPROTO_NETMGMT;
        auto e=CreateIpForwardEntry2(&row);if(e)throw Failure("STARTUP_FAILED: owned TUN route","TUN_ROUTE",e);routes.push_back(row);
    }
    void dns(uint64_t luid) {
        // Own only a new adapter; removing it restores its link-scoped DNS.
        struct Settings {ULONG version;ULONG64 flags;PWSTR domain,name_server,search_list;ULONG registration,adapter_name,llmnr,query_name;PWSTR profile;};
        HMODULE module=GetModuleHandleW(L"iphlpapi.dll");using Setter=DWORD(WINAPI*)(GUID,const Settings*);Setter setter=nullptr;auto raw=GetProcAddress(module,"SetInterfaceDnsSettings");std::memcpy(&setter,&raw,sizeof(setter));
        if(!setter)throw Failure("STARTUP_FAILED: Windows 10 build 19041 required","TUN_DNS_API");
        NET_LUID id{};id.Value=luid;GUID guid{};auto code=ConvertInterfaceLuidToGuid(&id,&guid);if(code)throw Failure("STARTUP_FAILED: TUN GUID","TUN_DNS_INTERFACE",code);
        for(unsigned v6=0;v6<2;++v6){Settings settings{};settings.version=1;settings.flags=0x2|0x8|0x80|(v6?1:0);settings.name_server=const_cast<wchar_t*>(v6?L"2620:fe::fe":L"9.9.9.9");code=setter(guid,&settings);if(code)throw Failure("STARTUP_FAILED: owned interface DNS","TUN_DNS",code);}
    }
    void configure(uint64_t luid,bool test) {
        for(ADDRESS_FAMILY family:{ADDRESS_FAMILY(AF_INET),ADDRESS_FAMILY(AF_INET6)}){MIB_IPINTERFACE_ROW row{};InitializeIpInterfaceEntry(&row);row.Family=family;row.InterfaceLuid.Value=luid;auto e=GetIpInterfaceEntry(&row);if(e)throw Failure("STARTUP_FAILED: TUN interface","TUN_INTERFACE",e);row.NlMtu=1500;row.UseAutomaticMetric=FALSE;row.Metric=5;row.DadTransmits=0;if((e=SetIpInterfaceEntry(&row)))throw Failure("STARTUP_FAILED: TUN MTU","TUN_MTU",e);}
        address(luid,"198.18.0.2",false,30);address(luid,"fd71:5650::2",true,126);
        if(!test)dns(luid);
        if(test){route(luid,"203.0.113.0",false,24);route(luid,"2001:db8::",true,32);}
        else{route(luid,"0.0.0.0",false,1);route(luid,"128.0.0.0",false,1);route(luid,"::",true,1);route(luid,"8000::",true,1);}
    }
};
std::string argument(const wchar_t* w){int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,w,-1,nullptr,0,nullptr,nullptr);if(n<1)throw Failure("STARTUP_FAILED: arguments","TUN_ARGUMENT");std::string s(size_t(n),'\0');WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,w,-1,s.data(),n,nullptr,nullptr);s.pop_back();return s;}
}
int wmain(int argc,wchar_t** argv) {
    using namespace vpn;
    HANDLE owner=CreateMutexW(nullptr,FALSE,L"Global\\VpnCoreNativeTunOwnerV1");
    if(!owner||GetLastError()==ERROR_ALREADY_EXISTS){if(owner)CloseHandle(owner);std::cerr<<"Native TUN is already active\n";return 2;}
    struct CloseOwner{HANDLE h;~CloseOwner(){CloseHandle(h);}} close_owner{owner};
    bool recover=false,test=false;std::string config_path,dll_path,name="VpnCore-TUN";Context context;
    try {
        NetworkRuntime network;
        for(int i=1;i<argc;++i){std::wstring a=argv[i];if(a==L"--recover-network")recover=true;else if(a==L"--test-routes")test=true;else if((a==L"--config"||a==L"--wintun"||a==L"--name"||a==L"--uplink-index")&&i+1<argc){auto s=argument(argv[++i]);if(a==L"--config")config_path=s;else if(a==L"--wintun")dll_path=s;else if(a==L"--name")name=s;else context.uplink=ULONG(number(s,1,0xffffffffu));}else throw Failure("STARTUP_FAILED: unknown argument","TUN_ARGUMENT");}
        NativeWindowsPolicy policy;if(recover){policy.recover();std::cout<<"Owned WFP policy recovered\n";return 0;}
        if(config_path.empty()||dll_path.empty()||context.uplink==0)throw Failure("STARTUP_FAILED: required arguments","TUN_ARGUMENT");
        auto config=read_config(config_path);require_supported(config);context.host=config.server;stopping=false;context.addresses=node_addresses(config.server,Clock::now()+std::chrono::milliseconds(config.connect_ms));
        vpn_core_tun_options options{sizeof(options),1,-1,VPN_CORE_TUN_WINTUN,1500,64,0,name.c_str(),dll_path.c_str()};SetConsoleCtrlHandler(console_stop,TRUE);
        auto worker=std::async(std::launch::async,[&]{return vpn_core_run_tun(config_path.c_str(),&options,protect_node,resolve_node,&context);});
        struct StopJoin{~StopJoin(){vpn_core_stop();}} stop_join;
        uint64_t luid=0;auto deadline=Clock::now()+std::chrono::seconds(15);
        while(!luid){char data[8192];int n=vpn_core_read_event(data,sizeof(data));if(n>0){auto e=json_parse(std::string(data,size_t(n)));if(e.at("event").scalar()=="tun_ready")luid=uint64_t(std::stoull(e.at("luid").scalar()));}if(worker.wait_for(std::chrono::milliseconds(0))==std::future_status::ready)throw Failure("STARTUP_FAILED: TUN worker failed","TUN_STARTUP");if(Clock::now()>=deadline)throw Failure("STARTUP_FAILED: readiness timeout","TUN_STARTUP_TIMEOUT");std::this_thread::sleep_for(std::chrono::milliseconds(5));}
        if(!test)policy.acquire(luid,context.addresses,config.port);
        OwnedRoutes routes;routes.configure(luid,test);
        NET_LUID interface_luid{};interface_luid.Value=luid;NET_IFINDEX index=0;ConvertInterfaceLuidToIndex(&interface_luid,&index);
        std::cout<<"{\"event\":\"native_tun_network_ready\",\"interface_index\":"<<index<<",\"test_routes\":"<<(test?"true":"false")<<"}"<<std::endl;
        while(worker.wait_for(std::chrono::milliseconds(50))!=std::future_status::ready){char data[8192];int n=vpn_core_read_event(data,sizeof(data));if(n>0)std::cout<<std::string(data,size_t(n))<<std::endl;}
        int result=worker.get();if(!test&&result==0)policy.recover();else if(!test)std::cerr<<"Core failed: kill switch retained. Use --recover-network to disconnect.\n";
        return result;
    }catch(const std::exception& e){auto f=dynamic_cast<const Failure*>(&e);vpn_core_stop();std::cerr<<"Native TUN failed: "<<(f?f->code:"TUN_STARTUP")<<" status="<<(f?f->native_status:0)<<"\n";return 1;}
}
