// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
#pragma once
#ifdef _WIN32
#define VPN_CORE_API __declspec(dllexport)
#else
#define VPN_CORE_API __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif
VPN_CORE_API const char* vpn_core_version(void);
// Blocking call: run on an application-owned worker thread. One run at a time.
// argv is borrowed only during this call. Returns 2 if another run is active.
VPN_CORE_API int vpn_core_run(int argc, char** argv);
// Request shutdown, then join the worker before unloading the core library.
VPN_CORE_API void vpn_core_stop(void);
#ifdef __cplusplus
}
#endif
