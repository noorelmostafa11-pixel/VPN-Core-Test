// Copyright (c) 2026 Vpn project owner (noorelmostafa11-pixel). See NOTICE.md.
#include "transport.hpp"
#include "xhttp-provider.hpp"
#include "version.hpp"
#include "core-api.h"
#include "core-events.hpp"
#include "udp-relay.hpp"
#include "native-tun-udp-protocol.hpp"
#include "native-tun-tcp-reliable.hpp"
#include "native-tun-tcp-socks.hpp"
#ifdef _WIN32
#include "native-tun-udp-pump.hpp"
#include "native-tun-ip-pump.hpp"
#endif
#include <atomic>
#include <csignal>
#include <future>
#include <iostream>
#include <mutex>
#include <thread>

namespace vpn {
static_assert(std::atomic<bool>::is_always_lock_free, "Signal handler needs lock-free atomics");
std::mutex log_mutex;
void stop_handler(int){stopping.store(true,std::memory_order_relaxed);}
uint64_t diagnostic_time(){return uint64_t(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());}
void diagnostic_identity(Json& j,uint64_t id){j["connection_id"]=Json::integer(id);j["timestamp_unix_ms"]=Json::integer(diagnostic_time());}
void log_line(const std::string& text){std::lock_guard<std::mutex> guard(log_mutex);std::cout<<text<<std::endl;}
void socks_reply(Socket& s,uint8_t code,Clock::time_point deadline) {
    uint8_t b[10]={5,code,0,1,0,0,0,0,0,0};send_all(s,b,sizeof(b),deadline);
}
Bytes socks_request(Socket& client,Clock::time_point deadline,uint8_t* command=nullptr) {
    auto hello=receive_exact(client,2,deadline);
    if(hello[0]!=5||hello[1]==0)throw std::runtime_error("Invalid SOCKS5 greeting");
    auto methods=receive_exact(client,hello[1],deadline);
    bool accepted=std::find(methods.begin(),methods.end(),0)!=methods.end();
    uint8_t selected[2]={5,uint8_t(accepted?0:255)};send_all(client,selected,2,deadline);
    if(!accepted)throw std::runtime_error("SOCKS5 authentication method unsupported");
    auto request=receive_exact(client,4,deadline);
    if(request[0]!=5||request[2]!=0){socks_reply(client,1,deadline);throw std::runtime_error("Malformed SOCKS5 request");}
    if(request[1]!=1&&request[1]!=3){socks_reply(client,7,deadline);throw std::runtime_error("Unsupported SOCKS5 command");}
    if(command)*command=request[1];
    Bytes address{request[3]};size_t length=0;
    if(request[3]==1)length=4;
    else if(request[3]==4)length=16;
    else if(request[3]==3){auto n=receive_exact(client,1,deadline);if(!n[0]){socks_reply(client,8,deadline);throw std::runtime_error("Empty destination hostname");}address.push_back(n[0]);length=n[0];}
    else{socks_reply(client,8,deadline);throw std::runtime_error("Unsupported destination address type");}
    auto body=receive_exact(client,length+2,deadline);address.insert(address.end(),body.begin(),body.end());
    if(request[1]==1&&body[body.size()-1]==0&&body[body.size()-2]==0){socks_reply(client,1,deadline);throw std::runtime_error("Destination port must be nonzero");}
    if(request[3]==3)for(size_t i=0;i<length;++i)if(body[i]<=32||body[i]>=127){socks_reply(client,8,deadline);throw std::runtime_error("Destination hostname requires ASCII/IDNA");}
    return address;
}
void relay(Socket& client,Socket& server,SecureStream& tls,Transport& transport,Protocol& protocol,const Config& config,const Bytes& initial,uint64_t& uploaded,uint64_t& downloaded) {
    constexpr size_t limit=524288;Queue up,down;bool client_eof=false,server_eof=false,transport_ended=false,server_write_closed=false;auto last=Clock::now();
    auto process=[&](const Bytes& b){up.append(tls.take_control());auto data=protocol.decode(transport.decode(b));if(protocol.take_direct()){auto held=tls.switch_direct_receive();auto direct=protocol.decode(transport.decode(held));data.insert(data.end(),direct.begin(),direct.end());}downloaded+=data.size();down.append(data);auto protocol_control=protocol.take_control();if(!protocol_control.empty()&&tls.write_open())up.append(tls.encrypt(transport.encode(protocol_control)));auto control=transport.take_control();if(!control.empty()&&tls.write_open())up.append(tls.encrypt(control));};
    process(initial);
    for(;;) {
        if(stopping)break;
        if(down.size()<limit-65536)process(tls.feed(nullptr,0));
        if(client_eof&&!transport_ended&&!protocol.pending_bytes()){auto close=transport.finish();if(!close.empty())up.append(tls.encrypt(close));if((config.transport=="raw"||config.transport=="httpupgrade"||config.transport=="obfs-http"||config.transport=="obfs-tls")&&tls.secure())up.append(tls.close_notify());transport_ended=true;}

        // Deliver FIN before waiting for a peer that is itself waiting for FIN.
        // With no final plaintext bytes, select could time out and skip shutdown.
        if(client_eof&&transport_ended&&!server_write_closed&&!protocol.pending_bytes()&&!tls.secure()&&(config.transport=="raw"||config.transport=="httpupgrade")&&up.empty()){
#ifdef _WIN32
            shutdown(server.get(),SD_SEND);
#else
            shutdown(server.get(),SHUT_WR);
#endif
            server_write_closed=true;
        }

        if((server_eof||tls.closed()||transport.closed()||protocol.closed())&&down.empty()&&up.empty())break;
        if(Clock::now()-last>std::chrono::milliseconds(config.idle_ms))throw std::runtime_error("IDLE_TIMEOUT: connection idle timeout");
        fd_set reads,writes;FD_ZERO(&reads);FD_ZERO(&writes);
        if(!client_eof&&!server_eof&&!tls.closed()&&!tls.negotiating()&&!transport.closed()&&!protocol.closed()&&up.size()+transport.pending_bytes()+tls.pending_bytes()+protocol.pending_bytes()<limit-65536)FD_SET(client.get(),&reads);
        if(!server_eof&&!tls.closed()&&!transport.closed()&&down.size()<limit-65536&&tls.pending_bytes()<196608)FD_SET(server.get(),&reads);
        if(!up.empty())FD_SET(server.get(),&writes);if(!down.empty())FD_SET(client.get(),&writes);
        if(!FD_ISSET(client.get(),&reads)&&!FD_ISSET(server.get(),&reads)&&!FD_ISSET(client.get(),&writes)&&!FD_ISSET(server.get(),&writes)){std::this_thread::sleep_for(std::chrono::milliseconds(1));continue;}
        timeval timeout{0,(tls.pending_bytes()||protocol.pending_bytes())?1000:50000};auto highest=std::max(client.get(),server.get());int result=select(int(highest+1),&reads,&writes,nullptr,&timeout);
        if(result<0){
#ifndef _WIN32
            if(errno==EINTR)continue;
#endif
            throw Failure("RELAY_FAILED: socket wait","RELAY_SOCKET_WAIT",uint32_t(socket_error()));
        }
        if(!result)continue;
        if(FD_ISSET(server.get(),&writes)){auto before=up.size();up.flush(server);if(up.size()<before)last=Clock::now();}
        if(FD_ISSET(client.get(),&writes)){auto before=down.size();down.flush(client);if(down.size()<before)last=Clock::now();}
        uint8_t buffer[16384];
        if(FD_ISSET(client.get(),&reads)){int n=client.receive(buffer,sizeof(buffer));if(n==0){client_eof=true;auto final=protocol.finish();if(!final.empty())up.append(tls.encrypt(transport.encode(final)));}
        
        else if(n>0){up.append(tls.encrypt(transport.encode(protocol.encode(Bytes(buffer,buffer+n)))));uploaded+=uint64_t(n);last=Clock::now();}}
        if(FD_ISSET(server.get(),&reads)){int n=server.receive(buffer,sizeof(buffer));if(n==0){server_eof=true;if(tls.secure()&&!tls.direct_receive()&&!tls.closed())throw std::runtime_error("TLS_FAILED: truncated TLS stream");}else if(n>0){process(tls.feed(buffer,size_t(n)));last=Clock::now();}}
    }
}
void relay_xhttp(Socket& client,XHttpStream& stream,Protocol& protocol,const Config& config,uint64_t& uploaded,uint64_t& downloaded){Queue down;Bytes pending;bool client_eof=false,finished=false,end_requested=false;auto last=Clock::now();for(;;){if(stopping)break;if(down.size()<524288-65536){auto bytes=stream.read();auto data=protocol.decode(bytes);if(protocol.take_direct())throw Failure("PROTOCOL_FAILED: Vision direct cannot bypass XHTTP framing","VISION_DIRECT_SECURITY");if(!data.empty()){downloaded+=data.size();down.append(data);last=Clock::now();}}if(pending.empty())pending=protocol.take_control();if(!pending.empty()&&stream.write(pending)){pending.clear();last=Clock::now();}if(client_eof&&pending.empty()&&!end_requested){pending=protocol.finish();end_requested=true;}if(end_requested&&pending.empty()&&!protocol.pending_bytes()&&!finished){stream.finish();finished=true;}if((stream.closed()||protocol.closed())&&down.empty())break;if(Clock::now()-last>std::chrono::milliseconds(config.idle_ms))throw Failure("RELAY_FAILED: XHTTP idle timeout","IDLE_TIMEOUT");fd_set reads,writes;FD_ZERO(&reads);FD_ZERO(&writes);if(!client_eof&&!stream.closed()&&!protocol.closed()&&pending.empty()&&stream.pending()+protocol.pending_bytes()<524288)FD_SET(client.get(),&reads);if(!down.empty())FD_SET(client.get(),&writes);if(!FD_ISSET(client.get(),&reads)&&!FD_ISSET(client.get(),&writes)){std::this_thread::sleep_for(std::chrono::milliseconds(5));continue;}timeval wait{0,5000};int result=select(int(client.get()+1),&reads,&writes,nullptr,&wait);if(result<0){
#ifndef _WIN32
if(errno==EINTR)continue;
#endif
throw Failure("RELAY_FAILED: XHTTP client wait","XHTTP_CLIENT_WAIT",uint32_t(socket_error()));}if(FD_ISSET(client.get(),&writes)){auto before=down.size();down.flush(client);if(down.size()<before)last=Clock::now();}if(FD_ISSET(client.get(),&reads)){uint8_t bytes[16384];int n=client.receive(bytes,sizeof(bytes));if(n==0)client_eof=true;else if(n>0){pending=protocol.encode(Bytes(bytes,bytes+n));uploaded+=uint64_t(n);last=Clock::now();}}}}
void connection(Socket client,const Config& config,uint64_t id) {
    std::string prefix="[connection "+std::to_string(id)+"] ",phase="SOCKS_FAILED",tls_version,alpn;uint64_t up=0,down=0;bool request_ok=false,tunnel_ready=false;
    try {
        auto deadline=Clock::now()+std::chrono::milliseconds(config.connect_ms);uint8_t command=1;auto destination=socks_request(client,deadline,&command);request_ok=true;
        if(command==3){phase="RELAY_FAILED";udp_associate(client,config,destination,tunnel_ready,stopping,up,down,[&](const std::string& code){Json event=Json::obj();diagnostic_identity(event,id);event["event"]=Json("udp_diagnostic");event["phase"]=Json("UDP");event["reason_code"]=Json(code);publish_event(event);log_line(prefix+"UDP reason_code="+code);});log_line(prefix+"UDP closed; uploaded="+std::to_string(up)+" downloaded="+std::to_string(down));return;}
        if(config.transport=="xhttp"||config.transport=="http"||config.transport=="kcp"||config.transport=="quic"){phase="PROTOCOL_FAILED";Protocol protocol(config);auto header=protocol.open(destination);phase="TRANSPORT_FAILED";XHttpStream stream;stream.open(config,header,deadline);auto metadata=stream.metadata();tls_version=metadata.at("version").scalar()=="772"?"TLS1.3":metadata.at("version").scalar()=="771"?"TLS1.2":"";alpn=metadata.at("alpn").scalar();socks_reply(client,0,deadline);tunnel_ready=true;Json negotiated=Json::obj();diagnostic_identity(negotiated,id);negotiated["event"]=Json("negotiated");negotiated["tls_version"]=Json(tls_version);negotiated["alpn"]=Json(alpn);publish_event(negotiated);log_line(prefix+"diagnostic="+json_dump(negotiated));log_line(prefix+"tunnel ready; protocol="+config.protocol+" transport="+config.transport+" tls="+tls_version+"; data transfer still unverified");phase="RELAY_FAILED";relay_xhttp(client,stream,protocol,config,up,down);log_line(prefix+"closed; uploaded="+std::to_string(up)+" downloaded="+std::to_string(down));return;}
        phase="CONNECT_FAILED";Socket server=connect_server(config,deadline);SecureStream tls;phase="TLS_FAILED";tls.handshake(server,config,deadline);tls_version=tls.version();alpn=tls.alpn();
        Transport transport(config);Protocol protocol(config);Bytes header;
        if(config.transport=="websocket"&&config.ws_early_data){phase="PROTOCOL_FAILED";header=transport.prepare(protocol.open(destination));}
        phase="TRANSPORT_FAILED";auto initial=transport.open(server,tls,deadline,header.empty()?nullptr:&header);
        phase="PROTOCOL_FAILED";if(config.transport=="websocket"&&config.ws_early_data){if(!header.empty())send_secure(server,tls,transport.encode_prepared(header),deadline);}else send_secure(server,tls,transport.encode(protocol.open(destination)),deadline);
        socks_reply(client,0,deadline);tunnel_ready=true;
        Json negotiated=Json::obj();diagnostic_identity(negotiated,id);negotiated["event"]=Json("negotiated");negotiated["tls_version"]=Json(tls_version);negotiated["alpn"]=Json(alpn);publish_event(negotiated);log_line(prefix+"diagnostic="+json_dump(negotiated));
        log_line(prefix+"tunnel ready; protocol="+config.protocol+" transport="+config.transport+" tls="+tls.version()+"; data transfer still unverified");
        phase="RELAY_FAILED";relay(client,server,tls,transport,protocol,config,initial,up,down);log_line(prefix+"closed; uploaded="+std::to_string(up)+" downloaded="+std::to_string(down));
    }catch(const std::exception& e){if(request_ok&&!tunnel_ready)try{socks_reply(client,1,Clock::now()+std::chrono::milliseconds(500));}catch(...){}std::string error=e.what();if(stopping)phase="CANCELLED";else if(error.find("DNS")!=std::string::npos)phase="DNS_FAILED";else if(error.find("timeout")!=std::string::npos)phase="TIMEOUT";else{auto colon=error.find(':');if(colon!=std::string::npos){auto p=error.substr(0,colon);const std::set<std::string> known{"TRANSPORT_FAILED","PROTOCOL_FAILED","TLS_FAILED","CONNECT_FAILED","RELAY_FAILED","FEATURE_UNIMPLEMENTED","PARSE_INVALID"};if(known.count(p))phase=p;}}
        Json detail=Json::obj();diagnostic_identity(detail,id);detail["event"]=Json("failure");detail["tunnel_ready"]=Json::boolean(tunnel_ready);detail["phase"]=Json(phase);auto f=dynamic_cast<const Failure*>(&e);detail["reason_code"]=Json(f?f->code:phase);detail["native_status"]=Json::integer(f?f->native_status:0);std::ostringstream hex;hex<<"0x"<<std::hex<<std::uppercase<<std::setfill('0')<<std::setw(8)<<(f?f->native_status:0);detail["native_status_hex"]=Json(hex.str());detail["http_status"]=Json::integer(f?f->http_status:0);detail["http_header_name"]=Json(f?f->http_header_name:"");detail["tls_version"]=Json(tls_version);detail["alpn"]=Json(alpn);publish_event(detail);log_line(prefix+"diagnostic="+json_dump(detail));
        log_line(prefix+"failed phase="+phase+": "+error+"; uploaded="+std::to_string(up)+" downloaded="+std::to_string(down));}
}

}
int run(int argc,char** argv,const vpn::NetworkHooks* hooks=nullptr) {
    using namespace vpn;
    static std::mutex run_mutex;
    std::unique_lock<std::mutex> active(run_mutex,std::try_to_lock);
    if(!active.owns_lock())return 2;
    reset_events();stopping.store(false,std::memory_order_relaxed);
    core_state.store(VPN_CORE_STARTING);bool configured_hooks=false;std::unique_ptr<NetworkRuntime> runtime;
    struct Cleanup {bool& configured;~Cleanup(){core_listen_port.store(0);if(configured)try{stopping.store(true);core_state.store(VPN_CORE_STOPPING);cancel_provider_network();configure_network_hooks({});}catch(...){}core_state.store(VPN_CORE_STOPPED);if(configured)log_line("Stopped");}} cleanup{configured_hooks};
    try {
        validate_xhttp_build=validate_xhttp_configuration;
        std::string config_path,list_path,native_tun_check_path;bool check=false,inspect=false;
        for(int i=1;i<argc;++i) {
            std::string a=argv[i];
            if(a=="--version"){std::cout<<"vpn-core " VPN_CORE_VERSION "-expanded; project-owned protocols; SOCKS5 CONNECT + UDP ASSOCIATE\n";return 0;}
            if(a=="--check-components"){(void)TlsProviderAPI::instance();(void)VlessEncryptionAPI::instance();(void)XHttpAPI::instance();std::cout<<"PASS: pinned TLS/HTTP and crypto component interfaces loaded\n";return 0;}
            if(a=="--self-test"){protocol_self_test();std::cout<<"PASS: SHA224, URI, AEAD and Poly1305 standard vector\n";return 0;}
            if(a=="--check-config")check=true;
            else if(a=="--inspect-config")inspect=true;
            else if(a=="--inspect-list"&&i+1<argc)list_path=argv[++i];
            else if(a=="--check-native-tun"&&i+1<argc)native_tun_check_path=argv[++i];
            else if(a=="--config"&&i+1<argc)config_path=argv[++i];
            else if(a=="--help"){std::cout<<"vpn-core --config node.ini [--check-config | --inspect-config]\nvpn-core --inspect-list nodes.txt\nvpn-core --self-test\nvpn-core --version\nvpn-core --check-native-tun <absolute-wintun-dll-path> (Windows only)\n";return 0;}
            else throw std::runtime_error("Unknown or incomplete command-line option");
        }
        if(!list_path.empty()){(void)TlsProviderAPI::instance();(void)VlessEncryptionAPI::instance();(void)XHttpAPI::instance();std::ifstream list(std::filesystem::u8path(list_path),std::ios::binary);if(!list)throw std::runtime_error("PARSE_INVALID: cannot open node list");std::string uri;uint64_t line=0;while(std::getline(list,uri)){++line;uri=trim(uri);if(uri.empty()||uri[0]=='#')continue;Json row=Json::obj();Config c;bool uri_parsed=false;try{parse_uri(c,uri);uri_parsed=true;row=inspection_fields(c);row=inspection(c);row["parsed"]=Json::boolean(true);}catch(const std::exception& e){row["parsed"]=Json::boolean(false);row["uri_parsed"]=Json::boolean(uri_parsed);row["config_valid"]=Json::boolean(false);row["connectable_by_this_build"]=Json::boolean(false);auto f=dynamic_cast<const Failure*>(&e);row["reason_code"]=Json(f?f->code:uri_parsed?"CONFIG_VALIDATION_INVALID":"URI_PARSE_INVALID");row["native_status"]=Json::integer(f?f->native_status:0);row["error"]=Json(e.what());}row["line"]=Json::integer(line);row["node_id"]=Json(hex_bytes(digest("sha256",to_bytes(uri))).substr(0,20));std::cout<<json_dump(row)<<'\n';}return 0;}
        if(!native_tun_check_path.empty()) {
#ifdef _WIN32
            const int size=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,native_tun_check_path.c_str(),-1,nullptr,0);
            if(size<=1)throw std::runtime_error("Native TUN DLL path has invalid UTF-8");
            std::wstring wide(size,L'\0');
            if(!MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,native_tun_check_path.c_str(),-1,wide.data(),size))
                throw std::runtime_error("Native TUN DLL path conversion failed");
            wide.pop_back();
            NativeWintunApi driver(wide);
            std::cout<<"PASS: Wintun API available; no adapter created or routes modified\n";
            return 0;
#else
            throw std::runtime_error("Native TUN is only available on Windows");
#endif
        }
        if(config_path.empty())throw std::runtime_error("Use --config node.ini; --help lists options");
        auto config=read_config(config_path);
        if(inspect){std::cout<<json_dump(inspection(config))<<'\n';return 0;}
        require_supported(config);
        if(check){std::cout<<"Config supported by this build; no network test performed\n";return 0;}
        network_dns_timeout.store(config.connect_ms);configured_hooks=true;configure_network_hooks(hooks?*hooks:NetworkHooks{},true);
        // Declared before Cleanup so Windows WSA lifetime extends through the
        // callback drain, including host resolvers that return after Stop.
        runtime=std::make_unique<NetworkRuntime>();Socket listener=listen_local(config.listen_port);
        sockaddr_in actual{};SockLen actual_size=sizeof(actual);if(getsockname(listener.get(),reinterpret_cast<sockaddr*>(&actual),&actual_size))throw Failure("STARTUP_FAILED: listener address","LISTENER_ADDRESS");config.listen_port=ntohs(actual.sin_port);core_listen_port.store(config.listen_port);
        core_state.store(stopping?VPN_CORE_STOPPING:VPN_CORE_RUNNING);
#ifndef VPN_CORE_SHARED
        std::signal(SIGINT,stop_handler);std::signal(SIGTERM,stop_handler);
#ifndef _WIN32
        std::signal(SIGPIPE,SIG_IGN);
#endif
#endif
        Tls label;log_line("vpn-core " VPN_CORE_VERSION "-expanded | "+std::string(label.backend()));
        if(!config.ready_file.empty()){if(std::filesystem::exists(std::filesystem::u8path(config.ready_file)))throw Failure("STARTUP_FAILED: ready file already exists","READY_FILE_EXISTS");sockaddr_in address{};
#ifdef _WIN32
            int size=sizeof(address);
#else
            socklen_t size=sizeof(address);
#endif
            if(getsockname(listener.get(),reinterpret_cast<sockaddr*>(&address),&size))throw Failure("STARTUP_FAILED: listener address","LISTENER_ADDRESS",uint32_t(socket_error()));config.listen_port=ntohs(address.sin_port);Json ready=Json::obj();ready["port"]=Json::integer(config.listen_port);ready["version"]=Json(VPN_CORE_VERSION "-expanded");
#ifdef _WIN32
            ready["pid"]=Json::integer(GetCurrentProcessId());
#else
            ready["pid"]=Json::integer(getpid());
#endif
std::ofstream f(std::filesystem::u8path(config.ready_file+".tmp"),std::ios::binary);f<<json_dump(ready);f.close();if(!f)throw Failure("STARTUP_FAILED: ready file write","READY_FILE_WRITE");std::filesystem::rename(std::filesystem::u8path(config.ready_file+".tmp"),std::filesystem::u8path(config.ready_file));}
        log_line("Listening SOCKS5 on 127.0.0.1:"+std::to_string(config.listen_port)+"; TCP CONNECT and UDP ASSOCIATE; Ctrl+C to stop");
        std::vector<std::future<void>> workers;uint64_t id=0;
        // Unwind cancellation before future destructors join connection workers.
        // This also covers listener errors, not only an explicit Stop request.
        struct StopBeforeJoin {~StopBeforeJoin(){stopping.store(true);core_state.store(VPN_CORE_STOPPING);core_listen_port.store(0);try{cancel_provider_network();}catch(...){}}} stop_before_join;
        while(!stopping) {
            for(auto it=workers.begin();it!=workers.end();) {if(it->wait_for(std::chrono::seconds(0))==std::future_status::ready){it->get();it=workers.erase(it);}else ++it;}
            fd_set reads;FD_ZERO(&reads);FD_SET(listener.get(),&reads);timeval timeout{0,20000};
            int r=select(int(listener.get()+1),&reads,nullptr,nullptr,&timeout);
            if(r<0){if(stopping)break;throw std::runtime_error("Listener wait failed");}if(!r)continue;
            if(stopping)break;Socket client(accept(listener.get(),nullptr,nullptr));if(client.get()==invalid_socket)continue;if(stopping)break;nonblocking(client.get());
            if(workers.size()>=config.max_connections){log_line("Connection limit reached; new client rejected");continue;}
            workers.push_back(std::async(std::launch::async,[client=std::move(client),&config,id=++id]()mutable{connection(std::move(client),config,id);}));
        }
        core_state.store(VPN_CORE_STOPPING);core_listen_port.store(0);listener=Socket();cancel_provider_network();
        for(auto& worker:workers)worker.get();
        return 0;
    } catch(const std::exception& e){auto f=dynamic_cast<const Failure*>(&e);Json j=Json::obj();diagnostic_identity(j,0);j["event"]=Json("failure");j["phase"]=Json("STARTUP_FAILED");j["reason_code"]=Json(f?f->code:"STARTUP_FAILED");j["native_status"]=Json::integer(f?f->native_status:0);j["http_status"]=Json::integer(0);j["tls_version"]=Json("");j["alpn"]=Json("");publish_event(j);std::cerr<<"[connection 0] diagnostic="<<json_dump(j)<<"\n";std::cerr<<"vpn-core: "<<e.what()<<"\n";return 1;}
}
#ifdef VPN_CORE_SHARED
extern "C" VPN_CORE_API const char* vpn_core_version(){return VPN_CORE_VERSION;}
extern "C" VPN_CORE_API int vpn_core_run(int argc,char** argv){if(argc<1||argc>64||!argv)return 1;for(int i=0;i<argc;++i)if(!argv[i])return 1;return run(argc,argv);}
extern "C" VPN_CORE_API void vpn_core_stop(){vpn::stopping.store(true,std::memory_order_relaxed);auto state=vpn::core_state.load();while(state!=VPN_CORE_STOPPED&&state!=VPN_CORE_STOPPING&&!vpn::core_state.compare_exchange_weak(state,VPN_CORE_STOPPING)){} }
extern "C" VPN_CORE_API uint32_t vpn_core_abi_version(){return 2;}
extern "C" VPN_CORE_API int vpn_core_get_state(){return vpn::core_state.load();}
extern "C" VPN_CORE_API uint16_t vpn_core_get_listen_port(){return vpn::core_listen_port.load();}
extern "C" VPN_CORE_API int vpn_core_read_event(char* output,uint32_t capacity){return vpn::read_event(output,capacity);}
extern "C" VPN_CORE_API uint32_t vpn_core_pending_callbacks(){std::lock_guard<std::mutex> lock(vpn::network_hooks_mutex);return vpn::network_hooks_active;}
extern "C" VPN_CORE_API int vpn_core_run_config(const char* path,vpn_core_socket_protector protect,vpn_core_resolver resolve,void* user){if(!path||!*path)return 1;char name[]="vpn-core",option[]="--config";char* args[]{name,option,const_cast<char*>(path)};vpn::NetworkHooks hooks{protect,resolve,user};return run(3,args,&hooks);}
#elif defined(_WIN32)
int wmain(int argc,wchar_t** argv) {
    std::vector<std::string> text;
    text.reserve(size_t(argc));
    for(int i=0;i<argc;++i) {
        int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,argv[i],-1,nullptr,0,nullptr,nullptr);
        if(!n){std::cerr<<"vpn-core: Invalid command-line text\n";return 1;}
        std::string s(size_t(n),'\0');
        WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,argv[i],-1,s.data(),n,nullptr,nullptr);
        s.pop_back();text.push_back(std::move(s));
    }
    std::vector<char*> args;for(auto& s:text)args.push_back(s.data());
    return run(argc,args.data());
}
#else
int main(int argc,char** argv){return run(argc,argv);}
#endif
