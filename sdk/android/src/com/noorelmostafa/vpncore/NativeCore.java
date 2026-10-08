package com.noorelmostafa.vpncore;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/** Blocking engine API. Run on an application-owned worker, join after stop. */
public final class NativeCore {
    public static final int STOPPED=0, STARTING=1, RUNNING=2, STOPPING=3;
    static {
        System.loadLibrary("vpn-tls");
        System.loadLibrary("vpn-core");
        System.loadLibrary("vpn-jni");
    }
    private NativeCore() {}

    /** Callbacks can arrive on native threads; return false/throw to fail closed. */
    public interface NetworkHooks {
        boolean protect(int socketFd);
        /** Numeric IP strings from the underlying Network.getAllByName(host). */
        String[] resolve(String hostname);
    }

    /** Returns 2 for an already active run, 1 for startup failure, 0 on stop. */
    public static int run(String configPath, NetworkHooks hooks) {
        Objects.requireNonNull(hooks, "VPN network hooks");
        return nativeRun(path(configPath), hooks);
    }
    /** Proxy-only use without a VpnService. */
    public static int runStandalone(String configPath) { return nativeRun(path(configPath), null); }
    private static byte[] path(String value) {
        Objects.requireNonNull(value, "configPath");
        if (value.isEmpty() || value.indexOf('\0') >= 0) throw new IllegalArgumentException("configPath");
        return value.getBytes(StandardCharsets.UTF_8);
    }
    private static native int nativeRun(byte[] configPath, NetworkHooks hooks);
    public static native void stop();
    public static native String version();
    public static native int abiVersion();
    public static native int state();
    /** Actual SOCKS TCP port; UDP ASSOCIATE returns its own UDP relay port. */
    public static native int listenPort();
    /** A JSON event, or null when the bounded queue is empty. */
    public static native String readEvent();
    /** Stop does not finish a non-cooperative callback; run drains its resources. */
    public static native int pendingCallbacks();
}
