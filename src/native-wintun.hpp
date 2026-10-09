// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
// Windows Wintun dynamic API loader. Loading only: no adapter or routing changes.
// The caller must own the adapter/session lifecycle and restore network settings.
#pragma once
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>

namespace vpn {
class NativeWintunApi final {
    HMODULE module_=nullptr;
    template<typename T> T symbol(const char* name) {
        auto p=GetProcAddress(module_,name);
        if(!p)throw std::runtime_error(std::string("Wintun export missing: ")+name);
        static_assert(sizeof(T)==sizeof(p), "Wintun function pointer size mismatch");
        T typed{};
        std::memcpy(&typed,&p,sizeof(typed));
        return typed;
    }
public:
    using Adapter=void*;
    using Session=void*;
    using CreateAdapterFn=Adapter(WINAPI*)(LPCWSTR,LPCWSTR,const GUID*);
    using OpenAdapterFn=Adapter(WINAPI*)(LPCWSTR);
    using CloseAdapterFn=void(WINAPI*)(Adapter);
    using StartSessionFn=Session(WINAPI*)(Adapter,DWORD);
    using EndSessionFn=void(WINAPI*)(Session);
    using GetReadWaitEventFn=HANDLE(WINAPI*)(Session);
    using ReceivePacketFn=BYTE*(WINAPI*)(Session,DWORD*);
    using ReleaseReceivePacketFn=void(WINAPI*)(Session,const BYTE*);
    using AllocateSendPacketFn=BYTE*(WINAPI*)(Session,DWORD);
    using SendPacketFn=void(WINAPI*)(Session,const BYTE*);

    CreateAdapterFn create_adapter=nullptr;
    OpenAdapterFn open_adapter=nullptr;
    CloseAdapterFn close_adapter=nullptr;
    StartSessionFn start_session=nullptr;
    EndSessionFn end_session=nullptr;
    GetReadWaitEventFn read_event=nullptr;
    ReceivePacketFn receive_packet=nullptr;
    ReleaseReceivePacketFn release_packet=nullptr;
    AllocateSendPacketFn allocate_packet=nullptr;
    SendPacketFn send_packet=nullptr;

    explicit NativeWintunApi(const std::wstring& absolute_dll_path) {
        if(absolute_dll_path.empty())throw std::invalid_argument("Wintun path is empty");
        // Reject relative paths: do not resolve arbitrary DLLs from PATH or CWD.
        const bool drive_absolute=absolute_dll_path.size()>=3&&
            ((absolute_dll_path[0]>=L'A'&&absolute_dll_path[0]<=L'Z')||
             (absolute_dll_path[0]>=L'a'&&absolute_dll_path[0]<=L'z'))&&
            absolute_dll_path[1]==L':'&&
            (absolute_dll_path[2]==L'\\'||absolute_dll_path[2]==L'/');
        if(!drive_absolute)throw std::invalid_argument("Wintun DLL requires a local absolute drive path");
        module_=LoadLibraryExW(absolute_dll_path.c_str(),nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        if(!module_)throw std::runtime_error("Cannot load pinned Wintun DLL");
        try {
            create_adapter=symbol<CreateAdapterFn>("WintunCreateAdapter");
            open_adapter=symbol<OpenAdapterFn>("WintunOpenAdapter");
            close_adapter=symbol<CloseAdapterFn>("WintunCloseAdapter");
            start_session=symbol<StartSessionFn>("WintunStartSession");
            end_session=symbol<EndSessionFn>("WintunEndSession");
            read_event=symbol<GetReadWaitEventFn>("WintunGetReadWaitEvent");
            receive_packet=symbol<ReceivePacketFn>("WintunReceivePacket");
            release_packet=symbol<ReleaseReceivePacketFn>("WintunReleaseReceivePacket");
            allocate_packet=symbol<AllocateSendPacketFn>("WintunAllocateSendPacket");
            send_packet=symbol<SendPacketFn>("WintunSendPacket");
        } catch(...) {
            FreeLibrary(module_);
            module_=nullptr;
            throw;
        }
    }
    ~NativeWintunApi(){if(module_)FreeLibrary(module_);}
    NativeWintunApi(const NativeWintunApi&)=delete;
    NativeWintunApi& operator=(const NativeWintunApi&)=delete;
    NativeWintunApi(NativeWintunApi&&)=delete;
    NativeWintunApi& operator=(NativeWintunApi&&)=delete;
};
} // namespace vpn
#endif
