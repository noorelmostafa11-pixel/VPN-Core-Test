// Independent packet/VLESS fixture. The tested data path contains no subprocess,
// SOCKS listener or alternate VPN engine. The peer is a local std::thread and
// parses VLESS wire bytes independently of Protocol, including original target.
#include "../src/netstack-core.hpp"
#include <future>
#include <iostream>
#include <cstring>
using namespace vpn;
static void require(bool condition,const char* text){if(!condition)throw std::runtime_error(text);}
static uint16_t u16(const uint8_t* p){return uint16_t(uint16_t(p[0])<<8|p[1]);}
static uint32_t u32(const uint8_t* p){return uint32_t(p[0])<<24|uint32_t(p[1])<<16|uint32_t(p[2])<<8|p[3];}
static void put16(uint8_t* p,uint16_t v){p[0]=uint8_t(v>>8);p[1]=uint8_t(v);}
static void put32(uint8_t* p,uint32_t v){p[0]=uint8_t(v>>24);p[1]=uint8_t(v>>16);p[2]=uint8_t(v>>8);p[3]=uint8_t(v);}
static uint32_t words(uint32_t sum,const uint8_t* p,size_t n){for(size_t i=0;i+1<n;i+=2)sum+=u16(p+i);if(n&1)sum+=uint32_t(p[n-1])<<8;return sum;}
static uint16_t checksum(uint32_t sum){while(sum>>16)sum=(sum&65535)+(sum>>16);return uint16_t(~sum);}
struct TestEndpoint {
    Bytes src,dst;
    uint16_t source_port=32123,target_port=443;
    explicit TestEndpoint(bool v6):src(v6?Bytes{0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,2}:Bytes{198,18,0,2}),dst(v6?Bytes{0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,9}:Bytes{203,0,113,9}){}
    Bytes packet(uint8_t protocol,const Bytes& payload,uint32_t seq=0,uint32_t ack=0,uint8_t flags=0)const {
        const size_t ip=src.size()==4?20:40,transport=protocol==6?20:8;
        Bytes p(ip+transport+payload.size());
        if(ip==20){p[0]=0x45;p[8]=64;p[9]=protocol;put16(p.data()+2,uint16_t(p.size()));std::copy(src.begin(),src.end(),p.begin()+12);std::copy(dst.begin(),dst.end(),p.begin()+16);put16(p.data()+10,checksum(words(0,p.data(),20)));}
        else {p[0]=0x60;p[6]=protocol;p[7]=64;put16(p.data()+4,uint16_t(p.size()-40));std::copy(src.begin(),src.end(),p.begin()+8);std::copy(dst.begin(),dst.end(),p.begin()+24);}
        auto* t=p.data()+ip;put16(t,source_port);put16(t+2,target_port);
        if(protocol==6){put32(t+4,seq);put32(t+8,ack);t[12]=0x50;t[13]=flags;put16(t+14,65535);}
        else put16(t+4,uint16_t(transport+payload.size()));
        std::copy(payload.begin(),payload.end(),p.begin()+std::ptrdiff_t(ip+transport));
        uint32_t sum=words(words(0,src.data(),src.size()),dst.data(),dst.size());sum+=protocol+uint32_t(transport+payload.size());
        auto check=checksum(words(sum,t,transport+payload.size()));if(protocol==17&&check==0)check=65535;
        put16(t+(protocol==6?16:6),check);return p;
    }
    struct Reply{uint8_t protocol=0,flags=0;uint32_t seq=0,ack=0;Bytes data;};
    Reply parse(const Bytes& p)const {
        require(!p.empty(),"empty packet");size_t ip=p[0]>>4==4?size_t(p[0]&15)*4:40;
        require(p.size()>=ip+8,"short response packet");
        bool ipv4=p[0]>>4==4;require((ipv4?4u:16u)==src.size(),"response address family");
        size_t s=ipv4?12:8,d=ipv4?16:24;
        require(std::equal(dst.begin(),dst.end(),p.begin()+std::ptrdiff_t(s))&&std::equal(src.begin(),src.end(),p.begin()+std::ptrdiff_t(d)),"response endpoint address changed");
        Reply r;r.protocol=p[ipv4?9:6];const auto* t=p.data()+ip;
        require(u16(t)==target_port&&u16(t+2)==source_port,"response endpoint port changed");
        size_t h=r.protocol==6?size_t(t[12]>>4)*4:8;require(p.size()>=ip+h,"response header");
        uint32_t sum=words(words(0,dst.data(),dst.size()),src.data(),src.size())+r.protocol+uint32_t(p.size()-ip);
        require(checksum(words(sum,t,p.size()-ip))==0,"response checksum");
        if(r.protocol==6){r.seq=u32(t+4);r.ack=u32(t+8);r.flags=t[13];}
        r.data.assign(p.begin()+std::ptrdiff_t(ip+h),p.end());return r;
    }
};
static std::atomic<unsigned> protected_count{0};
static int protector(int64_t,void*){++protected_count;return 1;}
static int resolver(const char* name,char* out,int capacity,void*){std::string value=std::string(name)=="fixture.invalid"?"127.0.0.1\n":"";if(value.empty()||capacity<=int(value.size()))return -1;std::memcpy(out,value.data(),value.size());return int(value.size());}
static Bytes trailer(){return to_bytes("AFTER-CLIENT-FIN");}
class VlessPeer {
    Socket listener_;
    std::thread thread_;
    std::exception_ptr error_;
    std::atomic<bool> done_{false};
    Bytes destination_;
    uint8_t command_;
public:
    uint16_t port=0;
    VlessPeer(const TestEndpoint& target,bool udp):destination_(target.dst),command_(udp?2:1) {
        listener_=listen_local(0);sockaddr_in a{};SockLen n=sizeof(a);require(getsockname(listener_.get(),reinterpret_cast<sockaddr*>(&a),&n)==0,"peer bind");port=ntohs(a.sin_port);
        thread_=std::thread([this,&target] {
            try {
                const auto deadline=Clock::now()+std::chrono::seconds(20);
                wait_socket(listener_.get(),false,deadline);
                Socket s(::accept(listener_.get(),nullptr,nullptr));require(s.get()!=invalid_socket,"peer accept");nonblocking(s.get());
                auto h=receive_exact(s,18,deadline);require(h[0]==0,"VLESS version");for(size_t i=1;i<17;++i)require(h[i]==0,"VLESS identity changed");
                (void)receive_exact(s,h[17],deadline);auto cmd=receive_exact(s,4,deadline);
                require(cmd[0]==command_&&u16(cmd.data()+1)==target.target_port,"VLESS command/target port changed");
                require(cmd[3]==(destination_.size()==4?1:3),"VLESS address type changed");require(receive_exact(s,destination_.size(),deadline)==destination_,"VLESS destination changed");
                const uint8_t response[]{0,0};send_all(s,response,2,deadline);
                uint8_t b[65535];
                if(command_==2) {
                    for(unsigned packet=0;packet<4;++packet){auto length=receive_exact(s,2,deadline);auto data=receive_exact(s,u16(length.data()),deadline);send_all(s,length.data(),length.size(),deadline);if(!data.empty())send_all(s,data.data(),data.size(),deadline);}
                    while(!done_&&Clock::now()<deadline)std::this_thread::sleep_for(std::chrono::milliseconds(1));
                } else for(;;){int count=s.receive(b,sizeof(b));if(count==-2){wait_socket(s.get(),false,deadline);continue;}if(!count){auto tail=trailer();send_all(s,tail.data(),tail.size(),deadline);break;}send_all(s,b,size_t(count),deadline);}
            }catch(...){error_=std::current_exception();}
        });
    }
    ~VlessPeer(){done_=true;if(thread_.joinable())thread_.join();}
    void finish(){done_=true;if(thread_.joinable())thread_.join();if(error_)std::rethrow_exception(error_);}
};
static Config fixture_config(uint16_t port) {
    Config c;parse_uri(c,"vless://00000000-0000-0000-0000-000000000000@fixture.invalid:"+std::to_string(port)+"?type=tcp&security=none");
    require(c.original_uri.find("fixture.invalid")!=std::string::npos,"parser source URI changed");c.connect_ms=5000;c.idle_ms=15000;return c;
}
template<class Pump,class Done>static void wait_until(Pump pump,Done done,const char* message) {
    auto deadline=Clock::now()+std::chrono::seconds(10);
    while(!done()){require(Clock::now()<deadline,message);pump();std::this_thread::sleep_for(std::chrono::milliseconds(1));}
}
static Json tcp_transfer(bool ipv6) {
    TestEndpoint endpoint(ipv6);VlessPeer peer(endpoint,false);auto config=fixture_config(peer.port);NetstackPackets stack;NetstackCoreBridge bridge(config,stack);
    uint32_t seq=1001,ack=0;bool established=false,fin=false;Bytes received;
    auto pump=[&] {
        bridge.poll();Bytes p;
        while(stack.packet(p)) {
            auto r=endpoint.parse(p);require(r.protocol==6,"non-TCP response");if(r.flags&4)throw std::runtime_error("TCP reset at client sequence "+std::to_string(seq));
            if(r.flags&2){require(r.ack==seq,"SYN acknowledgement");ack=r.seq+1;stack.inject(endpoint.packet(6,{},seq,ack,0x10));established=true;continue;}
            if(!r.data.empty()){if(r.seq==ack){append(received,r.data);ack+=uint32_t(r.data.size());}else require(int32_t(r.seq-ack)<0,"out of order test response");stack.inject(endpoint.packet(6,{},seq,ack,0x10));}
            if(r.flags&1){if(r.seq+uint32_t(r.data.size())==ack){++ack;fin=true;}stack.inject(endpoint.packet(6,{},seq,ack,0x10));}
        }
    };
    stack.inject(endpoint.packet(6,{},1000,0,2));wait_until(pump,[&]{return established;},"TCP handshake timeout");
    Bytes expected;auto start=Clock::now();
    for(unsigned chunk=0;chunk<64;++chunk){Bytes data(1000);for(size_t i=0;i<data.size();++i)data[i]=uint8_t(i+chunk*7);append(expected,data);stack.inject(endpoint.packet(6,data,seq,ack,0x18));seq+=uint32_t(data.size());wait_until(pump,[&]{return received.size()>=expected.size();},"TCP transfer timeout");require(received==expected,"TCP payload mismatch");}
    stack.inject(endpoint.packet(6,{},seq,ack,0x11));++seq;append(expected,trailer());
    wait_until(pump,[&]{return fin;},"TCP half-close timeout");require(received==expected,"TCP trailing data after FIN lost");peer.finish();
    Json result=stack.metrics();result["test"]=Json(ipv6?"TCP_IPV6":"TCP_IPV4");result["status"]=Json("PASS");result["payload_bytes"]=Json::integer(received.size());result["elapsed_us"]=Json::integer(uint64_t(std::chrono::duration_cast<std::chrono::microseconds>(Clock::now()-start).count()));result["half_close_trailing_data"]=Json::boolean(true);return result;
}
static Json udp_transfer(bool ipv6) {
    TestEndpoint endpoint(ipv6);VlessPeer peer(endpoint,true);auto config=fixture_config(peer.port);NetstackPackets stack;NetstackCoreBridge bridge(config,stack);
    size_t packets=0;Bytes received;bool delivered=false;auto start=Clock::now();
    auto pump=[&]{bridge.poll();Bytes p;while(stack.packet(p)){auto r=endpoint.parse(p);require(r.protocol==17,"non-UDP response");received=r.data;++packets;delivered=true;}};
    for(size_t size:{size_t(0),size_t(1),size_t(512),size_t(1200)}) {
        Bytes data(size);for(size_t i=0;i<size;++i)data[i]=uint8_t(i*17+size);delivered=false;stack.inject(endpoint.packet(17,data));wait_until(pump,[&]{return delivered;},"UDP transfer timeout");require(received==data,"UDP payload/boundary mismatch");
    }
    require(packets==4,"UDP duplicated/lost datagrams");peer.finish();auto result=stack.metrics();result["test"]=Json(ipv6?"UDP_IPV6":"UDP_IPV4");result["status"]=Json("PASS");result["datagrams"]=Json::integer(packets);result["empty_datagram"]=Json::boolean(true);result["elapsed_us"]=Json::integer(uint64_t(std::chrono::duration_cast<std::chrono::microseconds>(Clock::now()-start).count()));return result;
}
static Json copy_benchmark(size_t size) {
    NetstackPackets metrics_stack;auto& api=metrics_stack.api();Bytes input(size,0x79),output(size),middle(size);constexpr unsigned repetitions=2000;
    const auto before=metrics_stack.metrics();
    volatile uint64_t observed=0;auto start=Clock::now();
    for(unsigned i=0;i<repetitions;++i){input[0]=uint8_t(i);std::memcpy(middle.data(),input.data(),size);std::memcpy(output.data(),middle.data(),size);observed+=output[0];}
    auto cpp_ns=std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now()-start).count();start=Clock::now();
    for(unsigned i=0;i<repetitions;++i){input[0]=uint8_t(i);require(api.copy_probe(input.data(),output.data(),int(size))==int(size),"copy ABI failed");observed+=output[0];}
    auto abi_ns=std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now()-start).count();require(input==output&&observed>0,"copy benchmark contents");
    const auto after=metrics_stack.metrics();
    Json j=Json::obj();j["test"]=Json("CPP_GO_COPY");j["bytes"]=Json::integer(size);j["iterations"]=Json::integer(repetitions);j["cpp_two_copies_total_ns"]=Json::integer(uint64_t(cpp_ns));j["cpp_go_roundtrip_total_ns"]=Json::integer(uint64_t(abi_ns));j["go_memory_before"]=before;j["go_memory_after"]=after;j["status"]=Json("PASS");return j;
}
static uint64_t resource_count() {
#ifdef _WIN32
    DWORD count=0;require(GetProcessHandleCount(GetCurrentProcess(),&count)!=0,"handle count");return count;
#else
    uint64_t count=0;for(const auto& file:std::filesystem::directory_iterator("/proc/self/fd")){(void)file;++count;}return count;
#endif
}
static void cleanup_cycle() {
    TestEndpoint endpoint(false);NetstackPackets stack;
    stack.inject(endpoint.packet(17,{1,2,3}));NetstackFlow flow;
    wait_until([&]{},[&]{return stack.api().accept(stack.id(),&flow)==1;},"UDP cleanup accept");
    require(flow.protocol==17,"cleanup flow protocol");
    // Also tear down an incomplete TCP handshake, not just an empty stack.
    stack.inject(endpoint.packet(6,{},42,0,2));Bytes p;
    wait_until([&]{},[&]{return stack.packet(p);},"pending TCP cleanup handshake");
}
static Json resource_probe() {
    uint64_t previous=resource_count();unsigned unchanged=0;bool stable=false;
    for(unsigned i=0;i<24;++i){cleanup_cycle();auto n=resource_count();Json row=Json::obj();row["test"]=Json("RESOURCE_WARMUP");row["cycle"]=Json::integer(i);row["resources"]=Json::integer(n);row["status"]=Json("PASS");std::cout<<json_dump(row)<<'\n';unchanged=n==previous?unchanged+1:0;previous=n;if(unchanged>=4){stable=true;break;}}
    require(stable,"resource warmup did not stabilize within 24 cycles");const auto baseline=previous;
    for(unsigned i=0;i<32;++i){cleanup_cycle();auto n=resource_count();Json row=Json::obj();row["test"]=Json("RESOURCE_CYCLE");row["cycle"]=Json::integer(i);row["resources"]=Json::integer(n);row["baseline"]=Json::integer(baseline);row["status"]=Json(n<=baseline?"PASS":"FAIL");std::cout<<json_dump(row)<<'\n';require(n<=baseline,"packet stack resource count increased after stable warmup");}
    Json result=Json::obj();result["test"]=Json("RESOURCE_CLEANUP");result["cycles"]=Json::integer(32);result["baseline"]=Json::integer(baseline);result["status"]=Json("PASS");return result;
}
int main() {
    try {
        [[maybe_unused]] NetworkRuntime runtime;stopping=false;configure_network_hooks({protector,resolver,nullptr});
        std::cout<<json_dump(tcp_transfer(false))<<'\n'<<json_dump(tcp_transfer(true))<<'\n';
        std::cout<<json_dump(udp_transfer(false))<<'\n'<<json_dump(udp_transfer(true))<<'\n';
        for(size_t size:{size_t(64),size_t(512),size_t(1500),size_t(16384),size_t(65535)})std::cout<<json_dump(copy_benchmark(size))<<'\n';
        std::cout<<json_dump(resource_probe())<<'\n';
        require(protected_count>=4,"protector not used");configure_network_hooks({});
        std::cout<<"{\"test\":\"IN_PROCESS_EXISTING_CPP_ENGINE\",\"status\":\"PASS\",\"socks_listener\":false,\"subprocesses\":0}\n";return 0;
    }catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<'\n';return 1;}
}
