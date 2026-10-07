#pragma once
#include "config.hpp"
#include <cstring>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#include <unistd.h>
#endif
namespace vpn {
class ProviderModule {
#ifdef _WIN32
    HMODULE module_=nullptr;
    ProviderModule(){std::wstring path(32768,L'\0');HMODULE owner=nullptr;if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,reinterpret_cast<LPCWSTR>(&instance),&owner))throw Failure("TLS_FAILED: module path","TLS_PROVIDER_PATH");auto n=GetModuleFileNameW(owner,path.data(),DWORD(path.size()));if(!n||n>=path.size())throw Failure("TLS_FAILED: executable path","TLS_PROVIDER_PATH");path.resize(n);auto file=std::filesystem::path(path).parent_path()/L"vpn-tls.dll";module_=LoadLibraryExW(file.c_str(),nullptr,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);if(!module_)throw Failure("TLS_FAILED: cannot load provider","TLS_PROVIDER_LOAD",GetLastError());}
#else
    void* module_=nullptr;
    ProviderModule(){Dl_info info{};if(!dladdr(reinterpret_cast<const void*>(&instance),&info)||!info.dli_fname)throw Failure("TLS_FAILED: module path","TLS_PROVIDER_PATH");auto file=std::filesystem::absolute(info.dli_fname).parent_path()/"libvpn-tls.so";module_=dlopen(file.c_str(),RTLD_NOW|RTLD_LOCAL);if(!module_)throw Failure("TLS_FAILED: cannot load provider","TLS_PROVIDER_LOAD");}
#endif
public:
    template<class T>void symbol(T& pointer,const char* name){
#ifdef _WIN32
        auto raw=GetProcAddress(module_,name);
#else
        auto raw=dlsym(module_,name);
#endif
        if(!raw)throw Failure("TLS_FAILED: provider ABI symbol","TLS_PROVIDER_ABI");static_assert(sizeof(pointer)==sizeof(raw));std::memcpy(&pointer,&raw,sizeof(pointer));}
    static ProviderModule& instance(){static ProviderModule module;return module;}
};
}
