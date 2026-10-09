// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
#pragma once
#include <stdint.h>
#ifdef _WIN32
#ifdef VPN_CORE_SHARED
#define VPN_CORE_API __declspec(dllexport)
#else
#define VPN_CORE_API __declspec(dllimport)
#endif
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
// Request shutdown. Join the run worker before releasing hooks/user resources.
// Keep the core/provider modules loaded for the process lifetime.
VPN_CORE_API void vpn_core_stop(void);
// ABI 2 adds embedding hooks. ABI 1 functions remain available.
VPN_CORE_API uint32_t vpn_core_abi_version(void);
enum vpn_core_state { VPN_CORE_STOPPED=0, VPN_CORE_STARTING=1, VPN_CORE_RUNNING=2, VPN_CORE_STOPPING=3 };
VPN_CORE_API int vpn_core_get_state(void);
// Returns the actual bound SOCKS port, or zero before readiness/after shutdown.
VPN_CORE_API uint16_t vpn_core_get_listen_port(void);
// Additive ABI 2 event API: bounded queue of UTF-8 JSON diagnostics. Never contains
// credentials, addresses, resolver URLs or packet contents. One consumer at a time.
// Returns bytes excluding NUL, 0 if empty, or negative required capacity (includes
// NUL) without consuming an event. Events include connection_id and reason_code.
VPN_CORE_API int vpn_core_read_event(char* output, uint32_t capacity);
// Leases still holding application hook resources. May stay nonzero after Stop.
VPN_CORE_API uint32_t vpn_core_pending_callbacks(void);
// Return 1 to allow an outbound socket, 0 to reject it. Called before connect/send.
// The handle is an fd on Android/POSIX and a SOCKET on Windows; do not close it.
typedef int (*vpn_core_socket_protector)(int64_t socket_handle, void* user);
// Write newline-separated numeric IPv4/IPv6 addresses; return bytes written,
// or -1 on failure. Use the underlying Android Network for bootstrap lookup.
typedef int (*vpn_core_resolver)(const char* hostname, char* output, int capacity, void* user);
// Blocking, single-run entry point. Hooks stay valid until this call returns.
// They may run concurrently on core/provider threads and must not call run,
// reconfigure hooks, or synchronously wait for this run to finish from a callback.
// Resolver callbacks are bounded to 16 in flight. Timeout/Stop cancels waiting,
// not callback execution. This call drains ALL callback leases before returning.
// Null hooks preserve standalone behavior. Failed hooks never bypass the VPN.
VPN_CORE_API int vpn_core_run_config(const char* config_path,
    vpn_core_socket_protector protect, vpn_core_resolver resolve, void* user);
// Additive experimental TUN ABI 1. Existing core ABI 2 is unchanged.
// Callers own route/DNS/firewall transactions and protected bootstrap hooks.
// FD mode duplicates fd; caller retains its original and must do no I/O until
// run returns. Nonblocking flags affect the shared open-file description.
// Never close a supplied FD to Stop: call vpn_core_stop(), then join.
enum vpn_core_tun_kind { VPN_CORE_TUN_FD=0, VPN_CORE_TUN_LINUX=1, VPN_CORE_TUN_WINTUN=2 };
typedef struct vpn_core_tun_options {
    uint32_t size, abi;
    int64_t fd;
    uint32_t kind, mtu, maximum_flows, reserved;
    const char* interface_name;
    const char* wintun_path;
} vpn_core_tun_options;
// 1 when built with --experimental-netstack, otherwise 0.
VPN_CORE_API uint32_t vpn_core_tun_abi_version(void);
// Blocking. Returns 0 stopped, 1 failed, 2 busy, -5 feature not built.
// Non-null protection and resolver callbacks are mandatory (fail closed).
VPN_CORE_API int vpn_core_run_tun(const char* config_path,
    const vpn_core_tun_options* options, vpn_core_socket_protector protect,
    vpn_core_resolver resolve, void* user);
// Readiness is device+packet engine ready, not proof of node connectivity.
// Listen port stays zero in TUN mode. Interface/metrics are UTF-8 JSON events.
VPN_CORE_API int vpn_core_tun_ready(void);
#ifdef __cplusplus
}
#endif
