#pragma once
#include "fragment.hpp"
#include "network-hooks.hpp"
#include <chrono>
#include <cstring>
#include <utility>
#include <thread>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace vpn {
using Clock=std::chrono::steady_clock;
#ifdef _WIN32
using Handle=SOCKET;constexpr Handle invalid_socket=INVALID_SOCKET;
inline int socket_error(){return WSAGetLastError();}
inline bool would_block(int e){return e==WSAEWOULDBLOCK||e==WSAEINPROGRESS;}
inline void close_socket(Handle s){closesocket(s);}
inline void nonblocking(Handle s){u_long x=1;if(ioctlsocket(s,FIONBIO,&x))throw std::runtime_error("Socket setup failed");}
struct NetworkRuntime {NetworkRuntime(){WSADATA d{};if(WSAStartup(MAKEWORD(2,2),&d))throw std::runtime_error("Winsock initialization failed");}~NetworkRuntime(){WSACleanup();}};
#else
using Handle=int;constexpr Handle invalid_socket=-1;
inline int socket_error(){return errno;}
inline bool would_block(int e){return e==EAGAIN||e==EWOULDBLOCK||e==EINPROGRESS;}
inline void close_socket(Handle s){::close(s);}
inline void nonblocking(Handle s){auto f=fcntl(s,F_GETFL);if(f<0||fcntl(s,F_SETFL,f|O_NONBLOCK)<0)throw std::runtime_error("Socket setup failed");}
struct NetworkRuntime {};
#endif
class Socket {
    Handle h_=invalid_socket;
    FragmentMask mask_;std::vector<WireChunk> pending_;size_t chunk_=0,offset_=0,credit_=0;
    Clock::time_point write_deadline_=Clock::time_point::max();unsigned write_timeout_=60000;
    int raw_send(const uint8_t* p,size_t n) {
#ifdef _WIN32
        auto r=::send(h_,reinterpret_cast<const char*>(p),int(n),0);
#else
        auto r=::send(h_,p,n,MSG_NOSIGNAL);
#endif
        if(r<0){auto e=socket_error();if(would_block(e))return -2;throw Failure("Socket send failed","SOCKET_SEND",uint32_t(e));}
        if(r==0&&n)throw Failure("Socket send made no progress","SOCKET_SEND_ZERO");
        return int(r);
    }
public:
    Socket()=default;explicit Socket(Handle h):h_(h){}
    ~Socket(){if(h_!=invalid_socket)close_socket(h_);}
    Socket(const Socket&)=delete;Socket& operator=(const Socket&)=delete;
    Socket(Socket&& s) noexcept:h_(std::exchange(s.h_,invalid_socket)),mask_(std::move(s.mask_)),pending_(std::move(s.pending_)),chunk_(s.chunk_),offset_(s.offset_),credit_(s.credit_),write_deadline_(s.write_deadline_),write_timeout_(s.write_timeout_){}
    Socket& operator=(Socket&& s) noexcept {if(this!=&s){if(h_!=invalid_socket)close_socket(h_);h_=std::exchange(s.h_,invalid_socket);mask_=std::move(s.mask_);pending_=std::move(s.pending_);chunk_=s.chunk_;offset_=s.offset_;credit_=s.credit_;write_deadline_=s.write_deadline_;write_timeout_=s.write_timeout_;}return *this;}
    Handle get()const{return h_;}
    void mask(const Config& c){mask_=FragmentMask(c);write_timeout_=c.idle_ms;if(mask_.active()){int on=1;if(setsockopt(h_,IPPROTO_TCP,TCP_NODELAY,reinterpret_cast<const char*>(&on),sizeof(on)))throw Failure("Socket fragment setup failed","SOCKET_NODELAY",uint32_t(socket_error()));}}
    void write_deadline(Clock::time_point d){if(pending_.empty())write_deadline_=d;}
    int receive(uint8_t* p,size_t n) {
        auto r=::recv(h_,reinterpret_cast<char*>(p),int(n),0);
        if(r<0){auto e=socket_error();if(would_block(e))return -2;throw Failure("Socket receive failed","SOCKET_RECEIVE",uint32_t(e));}
        return int(r);
    }
    int send(const uint8_t* p,size_t n) {
        if(!n)return 0;if(!mask_.active())return raw_send(p,n);
        if(pending_.empty()){pending_=mask_.write(p,n);credit_=n;chunk_=offset_=0;if(write_deadline_==Clock::time_point::max())write_deadline_=Clock::now()+std::chrono::milliseconds(write_timeout_);}
        if(n<credit_)throw std::runtime_error("TRANSPORT_FAILED: fragment input accounting");
        while(chunk_<pending_.size()) {check_cancelled();
            if(Clock::now()>=write_deadline_)throw std::runtime_error("Connection/handshake timeout");
            auto& item=pending_[chunk_];if(offset_<item.bytes.size()){int r=raw_send(item.bytes.data()+offset_,item.bytes.size()-offset_);if(r==-2)return -2;offset_+=size_t(r);if(offset_<item.bytes.size())return -2;}
            auto until=Clock::now()+std::chrono::milliseconds(item.delay_after_ms);
            while(Clock::now()<until){check_cancelled();if(Clock::now()>=write_deadline_)throw std::runtime_error("Connection/handshake timeout");std::this_thread::sleep_for(std::min(std::chrono::milliseconds(20),std::chrono::duration_cast<std::chrono::milliseconds>(until-Clock::now())));}
            ++chunk_;offset_=0;
        }
        auto accepted=credit_;pending_.clear();credit_=0;write_deadline_=Clock::time_point::max();return int(accepted);
    }
};
inline bool wait_socket(Handle h,bool writing,Clock::time_point deadline) {
    for(;;) {
        check_cancelled();auto ms=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-Clock::now()).count();
        if(ms<=0)throw std::runtime_error("Connection/handshake timeout");
        fd_set f,errors;FD_ZERO(&f);FD_SET(h,&f);FD_ZERO(&errors);FD_SET(h,&errors);
        ms=std::min(ms,decltype(ms)(20));timeval tv{long(ms/1000),long(ms%1000*1000)};
        int r=select(int(h+1),writing?nullptr:&f,writing?&f:nullptr,&errors,&tv);
        if(r>0)return true;
        if(r==0)continue;
#ifndef _WIN32
        if(errno==EINTR)continue;
#endif
        throw std::runtime_error("Socket wait failed");
    }
}
inline void send_all(Socket& s,const uint8_t* p,size_t n,Clock::time_point deadline) {
    while(n){check_cancelled();s.write_deadline(deadline);int r=s.send(p,n);if(r==-2){wait_socket(s.get(),true,deadline);continue;}p+=r;n-=size_t(r);}
}
inline Bytes receive_exact(Socket& s,size_t n,Clock::time_point deadline) {
    Bytes out(n);size_t offset=0;
    while(offset<n){check_cancelled();int r=s.receive(out.data()+offset,n-offset);if(r==-2){wait_socket(s.get(),false,deadline);continue;}if(!r)throw std::runtime_error("Unexpected client EOF");offset+=size_t(r);}
    return out;
}
inline Bytes receive_some(Socket& s,Clock::time_point deadline) {
    Bytes b(16384);
    for(;;){check_cancelled();int r=s.receive(b.data(),b.size());if(r==-2){wait_socket(s.get(),false,deadline);continue;}if(!r)throw std::runtime_error("TLS handshake ended unexpectedly");b.resize(size_t(r));return b;}
}
// System DNS uses the same bounded, drainable worker lifetime as host callbacks.
inline std::vector<std::string> node_addresses(const std::string& host,Clock::time_point deadline){
    if(has_bootstrap_resolver())return bootstrap_addresses(host,deadline);
    addrinfo hints{};hints.ai_socktype=SOCK_STREAM;hints.ai_family=AF_UNSPEC;hints.ai_flags=AI_NUMERICHOST;addrinfo* numeric=nullptr;
    if(getaddrinfo(host.c_str(),nullptr,&hints,&numeric)==0){freeaddrinfo(numeric);return {host};}
    auto lease=std::make_shared<HookLease>(true);auto result=std::make_shared<DnsResult>();
    auto worker=launch_dns_worker(result,[lease,result,host]{
        std::string text;try{[[maybe_unused]] NetworkRuntime runtime;addrinfo h{};h.ai_family=AF_UNSPEC;h.ai_socktype=SOCK_STREAM;addrinfo* list=nullptr;
        if(getaddrinfo(host.c_str(),nullptr,&h,&list)==0){
            struct Cleanup{addrinfo* p;~Cleanup(){freeaddrinfo(p);}} cleanup{list};unsigned count=0;
            for(auto p=list;p&&count<32;p=p->ai_next){char address[1025];if(getnameinfo(p->ai_addr,int(p->ai_addrlen),address,sizeof(address),nullptr,0,NI_NUMERICHOST)==0){text+=address;text+='\n';++count;}}
        }}catch(...){}
        {std::lock_guard<std::mutex> lock(result->mutex);if(!text.empty()&&text.size()<sizeof(result->output)){std::memcpy(result->output,text.data(),text.size());result->size=int(text.size());}result->done=true;}result->ready.notify_all();
    });
    std::unique_lock<std::mutex> lock(result->mutex);
    while(!result->done){check_cancelled();if(Clock::now()>=deadline)throw Failure("DNS_FAILED: system resolver timeout","BOOTSTRAP_DNS_TIMEOUT");result->ready.wait_until(lock,std::min(deadline,Clock::now()+std::chrono::milliseconds(20)));}
    check_cancelled();lock.unlock();join_dns_worker(worker);if(result->size<=0)throw Failure("DNS_FAILED: system lookup failed","BOOTSTRAP_DNS_FAILED");
    std::istringstream input(std::string(result->output,size_t(result->size)));std::vector<std::string> out;std::string address;while(std::getline(input,address))out.push_back(address);return out;
}
inline Socket connect_server(const Config& c,Clock::time_point deadline) {
    addrinfo hint{};hint.ai_socktype=SOCK_STREAM;hint.ai_family=AF_UNSPEC;
    auto names=node_addresses(c.server,deadline);auto port=std::to_string(c.port);
    for(const auto& name:names){
    addrinfo* list=nullptr;
    hint.ai_flags=AI_NUMERICHOST;
    if(getaddrinfo(name.c_str(),port.c_str(),&hint,&list))continue;
    struct Cleanup{addrinfo* p;~Cleanup(){freeaddrinfo(p);}}cleanup{list};
    for(auto p=list;p;p=p->ai_next) {
        Socket s(::socket(p->ai_family,p->ai_socktype,p->ai_protocol));
        if(s.get()==invalid_socket)continue;
        auto allowed=protect_socket_callback(int64_t(s.get()),nullptr);check_cancelled();if(!allowed)throw Failure("CONNECT_FAILED: outbound socket protection rejected","SOCKET_PROTECTION_FAILED");
        nonblocking(s.get());
        int r=::connect(s.get(),p->ai_addr,int(p->ai_addrlen));
        if(r==0){s.mask(c);return s;}
        if(!would_block(socket_error()))continue;
        wait_socket(s.get(),true,deadline);
        int e=0;
#ifdef _WIN32
        int len=sizeof(e);
#else
        socklen_t len=sizeof(e);
#endif
        if(getsockopt(s.get(),SOL_SOCKET,SO_ERROR,reinterpret_cast<char*>(&e),&len)==0&&e==0){s.mask(c);return s;}
    }
    }
    throw std::runtime_error("CONNECT_FAILED: cannot connect to node server");
}
inline Socket listen_local(uint16_t port) {
    Socket s(::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP));
    if(s.get()==invalid_socket)throw Failure("STARTUP_FAILED: cannot create listener","LISTENER_CREATE",uint32_t(socket_error()));
#ifdef _WIN32
    int on=1;if(setsockopt(s.get(),SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<const char*>(&on),sizeof(on)))throw Failure("STARTUP_FAILED: cannot reserve local port","LISTENER_RESERVE",uint32_t(socket_error()));
#else
    int on=1;setsockopt(s.get(),SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on));
#endif
    sockaddr_in a{};a.sin_family=AF_INET;a.sin_port=htons(port);a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(bind(s.get(),reinterpret_cast<sockaddr*>(&a),sizeof(a))||listen(s.get(),64))throw Failure("STARTUP_FAILED: cannot bind/listen on local port","LISTENER_BIND",uint32_t(socket_error()));
    nonblocking(s.get());return s;
}
class Queue {
    Bytes b_;size_t offset_=0;
public:
    size_t size()const{return b_.size()-offset_;}
    bool empty()const{return size()==0;}
    void append(const Bytes& b){if(offset_){b_.erase(b_.begin(),b_.begin()+std::ptrdiff_t(offset_));offset_=0;}b_.insert(b_.end(),b.begin(),b.end());if(size()>1048576)throw std::runtime_error("Connection buffer limit exceeded");}
    void flush(Socket& s){if(empty())return;int n=s.send(b_.data()+offset_,size());if(n>0)offset_+=size_t(n);if(offset_==b_.size()){b_.clear();offset_=0;}}
};
}
