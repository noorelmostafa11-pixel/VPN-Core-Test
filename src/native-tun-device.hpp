// Owned, bounded packet I/O. Route/firewall policy is a separate transaction.
#pragma once
#include "netstack-core.hpp"
#ifdef _WIN32
#include "native-wintun.hpp"
#else
#include <poll.h>
#include <sys/ioctl.h>
#if defined(__linux__) && !defined(__ANDROID__)
#include <linux/if_tun.h>
#include <net/if.h>
#endif
#endif
namespace vpn {
class NativeTunDevice {
#ifdef _WIN32
    std::unique_ptr<NativeWintunApi> api_;
    NativeWintunApi::Adapter adapter_=nullptr;
    NativeWintunApi::Session session_=nullptr;
    static std::wstring wide(const char* s){if(!s)throw Failure("STARTUP_FAILED: missing Windows TUN path/name","TUN_ARGUMENT");int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s,-1,nullptr,0);if(n<=1)throw Failure("STARTUP_FAILED: invalid UTF-8","TUN_ARGUMENT");std::wstring w(size_t(n),L'\0');MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s,-1,w.data(),n);w.pop_back();return w;}
    void close()noexcept{if(session_){api_->end_session(session_);session_=nullptr;}if(adapter_){api_->close_adapter(adapter_);adapter_=nullptr;}}
#else
    int fd_=-1;
    void close()noexcept{if(fd_>=0){::close(fd_);fd_=-1;}}
#endif
    std::string name_;
    uint64_t luid_=0;
public:
    explicit NativeTunDevice(const vpn_core_tun_options& o) {
        try {
#ifdef _WIN32
            if(o.kind!=VPN_CORE_TUN_WINTUN||o.fd!=-1)throw Failure("STARTUP_FAILED: Windows TUN kind","TUN_ARGUMENT");
            auto name=wide(o.interface_name);if(name.size()>128)throw Failure("STARTUP_FAILED: adapter name","TUN_ARGUMENT");
            api_=std::make_unique<NativeWintunApi>(wide(o.wintun_path));
            adapter_=api_->create_adapter(name.c_str(),L"VpnCore",nullptr);
            if(!adapter_)throw Failure("STARTUP_FAILED: Wintun adapter","TUN_ADAPTER_CREATE",GetLastError());
            NET_LUID luid{};api_->get_adapter_luid(adapter_,&luid);luid_=luid.Value;
            session_=api_->start_session(adapter_,4u*1024u*1024u);
            if(!session_)throw Failure("STARTUP_FAILED: Wintun session","TUN_SESSION_CREATE",GetLastError());name_=o.interface_name;
#else
            if(o.kind==VPN_CORE_TUN_FD) {
                if(o.fd<0||o.fd>INT32_MAX)throw Failure("STARTUP_FAILED: TUN FD","TUN_ARGUMENT");
                fd_=fcntl(int(o.fd),F_DUPFD_CLOEXEC,3);if(fd_<0)throw Failure("STARTUP_FAILED: duplicate TUN FD","TUN_FD_DUP",errno);
                name_=o.interface_name?o.interface_name:"application-tun";
            }else {
#if defined(__linux__) && !defined(__ANDROID__)
                if(o.kind!=VPN_CORE_TUN_LINUX||!o.interface_name||std::strlen(o.interface_name)>=IFNAMSIZ)throw Failure("STARTUP_FAILED: TUN interface name","TUN_ARGUMENT");
                fd_=::open("/dev/net/tun",O_RDWR|O_NONBLOCK|O_CLOEXEC);if(fd_<0)throw Failure("STARTUP_FAILED: open /dev/net/tun","TUN_DEVICE_OPEN",errno);
                ifreq request{};request.ifr_flags=IFF_TUN|IFF_NO_PI;std::memcpy(request.ifr_name,o.interface_name,std::strlen(o.interface_name));
                if(ioctl(fd_,TUNSETIFF,&request)<0)throw Failure("STARTUP_FAILED: TUNSETIFF","TUN_DEVICE_CONFIGURE",errno);name_=request.ifr_name;
#else
                throw Failure("STARTUP_FAILED: Android requires VpnService FD","TUN_ARGUMENT");
#endif
            }
            // dup shares file status flags. The contract grants this run sole
            // I/O ownership; the original descriptor remains caller-owned.
            int flags=fcntl(fd_,F_GETFL);if(flags<0||fcntl(fd_,F_SETFL,flags|O_NONBLOCK)<0)throw Failure("STARTUP_FAILED: TUN nonblocking","TUN_NONBLOCK",errno);
#endif
        }catch(...){close();throw;}
    }
    ~NativeTunDevice(){close();}
    NativeTunDevice(const NativeTunDevice&)=delete;
    const std::string& name()const noexcept{return name_;}
    uint64_t luid()const noexcept{return luid_;}
    bool read(Bytes& p,unsigned wait_ms=5,int64_t wake_handle=-1) {
        p.clear();check_cancelled();
#ifdef _WIN32
        DWORD size=0;BYTE* data=api_->receive_packet(session_,&size);
        if(!data){DWORD error=GetLastError();if(error==ERROR_NO_MORE_ITEMS){HANDLE events[]{api_->read_event(session_),reinterpret_cast<HANDLE>(uintptr_t(wake_handle))};auto r=wake_handle>=0?WaitForMultipleObjects(2,events,FALSE,wait_ms):WaitForSingleObject(events[0],wait_ms);if(r==WAIT_FAILED)throw Failure("RELAY_FAILED: Wintun wait","TUN_READ_WAIT",GetLastError());return false;}throw Failure("RELAY_FAILED: Wintun receive","TUN_READ",error);}
        try{p.assign(data,data+size);}catch(...){api_->release_packet(session_,data);throw;}api_->release_packet(session_,data);return true;
#else
        pollfd events[2]{{fd_,POLLIN,0},{int(wake_handle),POLLIN,0}};int ready=::poll(events,wake_handle>=0?2:1,int(wait_ms));if(ready<0){if(errno==EINTR)return false;throw Failure("RELAY_FAILED: TUN wait","TUN_READ_WAIT",errno);}if(!ready||!(events[0].revents&(POLLIN|POLLERR|POLLHUP)))return false;
        p.resize(65535);auto n=::read(fd_,p.data(),p.size());if(n<0){p.clear();if(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR)return false;throw Failure("RELAY_FAILED: TUN read","TUN_READ",errno);}if(n==0)throw Failure("RELAY_FAILED: TUN device closed","TUN_DEVICE_CLOSED");p.resize(size_t(n));return true;
#endif
    }
    bool write(const Bytes& p) {
        check_cancelled();if(p.empty()||p.size()>65535)throw Failure("RELAY_FAILED: TUN packet size","TUN_PACKET_SIZE");
#ifdef _WIN32
        BYTE* data=api_->allocate_packet(session_,DWORD(p.size()));if(!data){DWORD e=GetLastError();if(e==ERROR_BUFFER_OVERFLOW)return false;throw Failure("RELAY_FAILED: Wintun allocate","TUN_WRITE",e);}std::memcpy(data,p.data(),p.size());api_->send_packet(session_,data);return true;
#else
        auto n=::write(fd_,p.data(),p.size());if(n<0){if(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR)return false;throw Failure("RELAY_FAILED: TUN write","TUN_WRITE",errno);}if(n!=ssize_t(p.size()))throw Failure("RELAY_FAILED: partial TUN datagram","TUN_WRITE_PARTIAL");return true;
#endif
    }
};
}
