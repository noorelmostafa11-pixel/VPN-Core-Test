// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
// Experimental native Windows TUN I/O. No route or DNS changes are made here.
// Not a TCP/IP stack: received packets are not forwarded anywhere.
#pragma once
#ifdef _WIN32
#include "native-tun-packet.hpp"
#include "native-wintun.hpp"
#include <atomic>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace vpn {
enum class NativeTunReadStatus { empty, accepted, dropped, stopped };

class NativeWintunSession final {
    NativeWintunApi& api_;
    NativeWintunApi::Adapter adapter_=nullptr;
    NativeWintunApi::Session session_=nullptr;
    std::atomic<bool> stopped_{false};
    uint64_t accepted_=0, dropped_=0;

    void close() noexcept {
        if(session_) {api_.end_session(session_); session_=nullptr;}
        if(adapter_) {api_.close_adapter(adapter_); adapter_=nullptr;}
    }
public:
    // Caller must have administrator rights, own this unique adapter name and
    // join its read worker BEFORE destroying the session or the API loader.
    NativeWintunSession(NativeWintunApi& api,const std::wstring& unique_name)
        :api_(api) {
        if(unique_name.empty()||unique_name.size()>128)
            throw std::invalid_argument("Native TUN adapter name is invalid");
        adapter_=api_.create_adapter(unique_name.c_str(),L"VpnCore",nullptr);
        if(!adapter_)throw std::runtime_error("Native TUN adapter creation failed: "+std::to_string(GetLastError()));
        session_=api_.start_session(adapter_,DWORD(4u*1024u*1024u));
        if(!session_) {
            const DWORD code=GetLastError();
            close();
            throw std::runtime_error("Native TUN session start failed: "+std::to_string(code));
        }
    }
    ~NativeWintunSession(){request_stop();close();}
    NativeWintunSession(const NativeWintunSession&)=delete;
    NativeWintunSession& operator=(const NativeWintunSession&)=delete;
    NativeWintunSession(NativeWintunSession&&)=delete;
    NativeWintunSession& operator=(NativeWintunSession&&)=delete;

    void request_stop() noexcept {stopped_.store(true,std::memory_order_relaxed);}
    uint64_t accepted_packets() const noexcept {return accepted_;}
    uint64_t dropped_packets() const noexcept {return dropped_;}

    // Single-reader contract. At most 50 ms is spent waiting for a read event.
    // The caller owns any further processing; this method never forwards.
    NativeTunReadStatus read(std::vector<uint8_t>& output,
                            NativeTunVerdict& verdict,DWORD wait_ms=20) {
        output.clear();
        verdict=NativeTunVerdict::malformed;
        if(stopped_.load(std::memory_order_relaxed))return NativeTunReadStatus::stopped;
        DWORD size=0;
        BYTE* received=api_.receive_packet(session_,&size);
        if(!received) {
            const DWORD code=GetLastError();
            if(code!=ERROR_NO_MORE_ITEMS)
                throw std::runtime_error("Native TUN receive failed: "+std::to_string(code));
            HANDLE event=api_.read_event(session_);
            if(!event)throw std::runtime_error("Native TUN read event is unavailable");
            const DWORD result=WaitForSingleObject(event,wait_ms>50?50:wait_ms);
            if(result==WAIT_FAILED)
                throw std::runtime_error("Native TUN read wait failed: "+std::to_string(GetLastError()));
            return stopped_.load(std::memory_order_relaxed)?
                NativeTunReadStatus::stopped:NativeTunReadStatus::empty;
        }
        struct ReceiveLease {
            NativeWintunApi& api;
            NativeWintunApi::Session session;
            const BYTE* data;
            ~ReceiveLease(){api.release_packet(session,data);}
        } lease{api_,session_,received};
        // Never copy malformed or oversized raw packets into an unbounded queue.
        const auto inspected=inspect_native_tun_packet(received,size);
        verdict=inspected.verdict;
        if(verdict!=NativeTunVerdict::tcp&&verdict!=NativeTunVerdict::udp) {
            ++dropped_;
            return NativeTunReadStatus::dropped;
        }
        if(stopped_.load(std::memory_order_relaxed))
            return NativeTunReadStatus::stopped;
        output.assign(received,received+size);
        ++accepted_;
        return NativeTunReadStatus::accepted;
    }

    // Single-writer contract. Use ONLY with authenticated traffic from the
    // future VPN protocol path. Calling this with arbitrary packets is unsafe.
    bool inject(const uint8_t* packet,size_t size) {
        if(stopped_.load(std::memory_order_relaxed))return false;
        const auto inspected=inspect_native_tun_packet(packet,size);
        if(inspected.verdict!=NativeTunVerdict::tcp&&
           inspected.verdict!=NativeTunVerdict::udp)return false;
        BYTE* dst=api_.allocate_packet(session_,DWORD(size));
        if(!dst)throw std::runtime_error("Native TUN transmit allocation failed: "+std::to_string(GetLastError()));
        std::memcpy(dst,packet,size);
        api_.send_packet(session_,dst);
        return true;
    }
};
} // namespace vpn
#endif
