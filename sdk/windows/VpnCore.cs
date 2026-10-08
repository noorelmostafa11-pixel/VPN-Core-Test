// .NET 6+ embedding adapter. Keep these DLLs beside the application:
// vpn-core.dll, vpn-tls.dll. Run() blocks; call it on an owned worker thread.
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace VpnCoreSdk;
public static class VpnCore
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int ProtectCallback(long socket, IntPtr user);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int ResolveCallback(IntPtr host, IntPtr output, int capacity, IntPtr user);
    private static readonly IntPtr Module = NativeLibrary.Load(Path.Combine(AppContext.BaseDirectory, "vpn-core.dll"));
    private static T Export<T>(string name) where T:Delegate => Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(Module,name));
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate IntPtr VersionFunction();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint AbiFunction();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int StateFunction();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate ushort PortFunction();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void StopFunction();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int EventFunction([Out] byte[] output,uint capacity);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int RunFunction([MarshalAs(UnmanagedType.LPUTF8Str)] string config,
        ProtectCallback? protect, ResolveCallback? resolve, IntPtr user);
    private static readonly VersionFunction vpn_core_version=Export<VersionFunction>("vpn_core_version");
    private static readonly AbiFunction vpn_core_abi_version=Export<AbiFunction>("vpn_core_abi_version");
    private static readonly StateFunction vpn_core_get_state=Export<StateFunction>("vpn_core_get_state");
    private static readonly PortFunction vpn_core_get_listen_port=Export<PortFunction>("vpn_core_get_listen_port");
    private static readonly StopFunction vpn_core_stop=Export<StopFunction>("vpn_core_stop");
    private static readonly RunFunction vpn_core_run_config=Export<RunFunction>("vpn_core_run_config");
    private static readonly EventFunction vpn_core_read_event=Export<EventFunction>("vpn_core_read_event");
    private static readonly AbiFunction vpn_core_pending_callbacks=Export<AbiFunction>("vpn_core_pending_callbacks");
    public static uint PendingCallbacks => vpn_core_pending_callbacks();
    public static string? ReadEvent() { var output=new byte[4096];int n=vpn_core_read_event(output,(uint)output.Length);return n>0?Encoding.UTF8.GetString(output,0,n):null; }
    public static string Version => Marshal.PtrToStringUTF8(vpn_core_version())!;
    public static uint AbiVersion => vpn_core_abi_version();
    public static int State => vpn_core_get_state();
    public static ushort ListenPort => vpn_core_get_listen_port();
    public static void Stop() => vpn_core_stop();
    public static int Run(string config, Func<long,bool>? protect=null,
        Func<string,IEnumerable<IPAddress>>? resolve=null)
    {
        if (string.IsNullOrEmpty(config) || config.Contains('\0')) throw new ArgumentException("config");
        ProtectCallback? p = protect is null ? null : (socket, _) => {
            try { return protect(socket) ? 1 : 0; } catch { return 0; }
        };
        ResolveCallback? r = resolve is null ? null : (host, output, capacity, _) => {
            try {
                var text = string.Join("\n", resolve(Marshal.PtrToStringUTF8(host)!))+"\n";
                var bytes = Encoding.UTF8.GetBytes(text);
                if (bytes.Length >= capacity) return -1;
                Marshal.Copy(bytes, 0, output, bytes.Length); return bytes.Length;
            } catch { return -1; }
        };
        try { return vpn_core_run_config(config,p,r,IntPtr.Zero); }
        finally { GC.KeepAlive(p); GC.KeepAlive(r); }
    }
}
