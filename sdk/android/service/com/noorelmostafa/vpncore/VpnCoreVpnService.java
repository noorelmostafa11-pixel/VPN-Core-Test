package com.noorelmostafa.vpncore;

import android.app.*;
import android.content.*;
import android.net.*;
import android.os.*;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;

/** In-process integration service. Call VpnService.prepare from your Activity.
 * Retains TUN on transient core failure/network loss; reconnect recreates
 * protocol sessions on the same VPN. Only explicit Disconnect closes TUN.
 * System always-on + "Block connections without VPN" is required to preserve
 * fail-closed behavior across Android killing/crashing the entire application.
 */
public class VpnCoreVpnService extends VpnService {
    public static final String CONNECT="com.noorelmostafa.vpncore.CONNECT";
    public static final String DISCONNECT="com.noorelmostafa.vpncore.DISCONNECT";
    public static final String CONFIG="configPath";
    private final ScheduledExecutorService lifecycle=Executors.newSingleThreadScheduledExecutor();
    private volatile Network underlying;
    private ParcelFileDescriptor tun;
    private Thread worker;
    private volatile boolean disconnected=true;
    private String config;
    private ConnectivityManager connectivity;
    private ConnectivityManager.NetworkCallback callback;
    private volatile long generation;private int retry;
    @Override public void onCreate(){
        super.onCreate();connectivity=(ConnectivityManager)getSystemService(CONNECTIVITY_SERVICE);
        callback=new ConnectivityManager.NetworkCallback(){
            @Override public void onAvailable(Network network){
                lifecycle.execute(()->{if(disconnected)return;Network selected=chooseNetwork();if(selected==null||selected.equals(underlying))return;underlying=selected;setUnderlyingNetworks(new Network[]{selected});retry=0;restart();});
            }
            @Override public void onLost(Network network){
                lifecycle.execute(()->{if(network.equals(underlying)){underlying=null;stopWorker();underlying=chooseNetwork();if(underlying!=null){setUnderlyingNetworks(new Network[]{underlying});restart();}/* Keep TUN/routes closed while offline. */}});
            }
        };
        NetworkRequest request=new NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build();
        connectivity.registerNetworkCallback(request,callback);
    }
    private void foreground(){
        NotificationManager manager=(NotificationManager)getSystemService(NOTIFICATION_SERVICE);
        if(Build.VERSION.SDK_INT>=26)manager.createNotificationChannel(new NotificationChannel("vpn-core","VPN connection",NotificationManager.IMPORTANCE_LOW));
        Notification.Builder builder=Build.VERSION.SDK_INT>=26?new Notification.Builder(this,"vpn-core"):new Notification.Builder(this);
        builder.setContentTitle("VPN Core experiment").setContentText("Native tunnel active").setSmallIcon(android.R.drawable.stat_sys_warning);
        startForeground(7617,builder.build());
    }
    @Override public int onStartCommand(Intent intent,int flags,int id){
        if(intent!=null&&DISCONNECT.equals(intent.getAction())){lifecycle.execute(this::disconnect);return START_NOT_STICKY;}
        foreground();
        String provided=intent==null?null:intent.getStringExtra(CONFIG);
        final String path=provided!=null?provided:getSharedPreferences("vpn-core-tun",MODE_PRIVATE).getString(CONFIG,null);
        if(path==null){report("CONFIG_REQUIRED",1);stopSelf();return START_NOT_STICKY;}
        lifecycle.execute(()->{try{connect(path);}catch(Exception e){report("START_FAILED",1);/* An established TUN is retained fail closed. */}});
        return START_NOT_STICKY;
    }
    protected void report(String event,int result){android.util.Log.i("VpnCoreService",event+" result="+result);}
    private Network chooseNetwork(){
        Network active=connectivity.getActiveNetwork();if(usable(active,false))return active;
        for(Network network:connectivity.getAllNetworks())if(usable(network,true))return network;
        for(Network network:connectivity.getAllNetworks())if(usable(network,false))return network;return null;
    }
    private boolean usable(Network network,boolean validated){
        if(network==null)return false;NetworkCapabilities c=connectivity.getNetworkCapabilities(network);
        return c!=null&&c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)&&c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)&&!c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)&&(!validated||c.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED));
    }
    private void connect(String path)throws IOException {
        if(path==null||!new File(path).isFile())throw new IOException("configPath");
        if(tun!=null){disconnect();foreground();}
        if(prepare(this)!=null)throw new IOException("VPN consent required");
        config=path;getSharedPreferences("vpn-core-tun",MODE_PRIVATE).edit().putString(CONFIG,path).apply();underlying=chooseNetwork();if(underlying==null)throw new IOException("Underlying network unavailable");
        Builder builder=new Builder().setSession("VpnCore Native TUN").setMtu(1500).setBlocking(false)
            .addAddress("198.18.0.2",30).addAddress("fd71:5650::2",126)
            .addRoute("0.0.0.0",0).addRoute("::",0).addDnsServer("9.9.9.9").addDnsServer("2620:fe::fe")
            .setUnderlyingNetworks(new Network[]{underlying});
        // No allowBypass and no per-app exclusion: all device apps use VPN.
        tun=builder.establish();if(tun==null)throw new IOException("TUN establish failed");
        disconnected=false;retry=0;restart();
    }
    private void stopWorker(){
        ++generation;Thread owned=worker;if(owned==null)return;
        NativeCore.stop();try{owned.join();}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IllegalStateException("Join interrupted; retain TUN and hooks",e);}worker=null;
    }
    private void restart(){
        if(disconnected||tun==null||underlying==null)return;stopWorker();
        final Network selected=underlying;final int fd=tun.getFd();final String path=config;final long token=++generation;
        NativeCore.NetworkHooks hooks=new NativeCore.NetworkHooks(){
            @Override public boolean protect(int socketFd){
                if(!VpnCoreVpnService.this.protect(socketFd)){report("SOCKET_PROTECT_DENIED",1);return false;}
                try(ParcelFileDescriptor borrowed=ParcelFileDescriptor.fromFd(socketFd)){
                    long deadline=System.nanoTime()+2000000000L;
                    for(;;){
                        if(disconnected||token!=generation||!selected.equals(underlying))return false;
                        try{selected.bindSocket(borrowed.getFileDescriptor());break;}
                        catch(java.net.SocketException e){
                            if(e.getMessage()==null||!e.getMessage().contains("EPERM")||System.nanoTime()>=deadline)throw e;
                            // Await a bounded OS permission transition using the
                            // same protected socket and selected network; never bypass.
                            try{Thread.sleep(20);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();return false;}
                        }
                    }
                    if(!VpnCoreVpnService.this.protect(socketFd)){report("SOCKET_REPROTECT_DENIED",1);return false;}return true;
                }catch(IOException e){android.util.Log.i("VpnCoreService","SOCKET_BIND_FAILED "+e.getClass().getSimpleName()+": "+e.getMessage());return false;}
            }
            @Override public String[] resolve(String host){try{InetAddress[] list=selected.getAllByName(host);String[] ips=new String[list.length];for(int i=0;i<list.length;i++)ips[i]=list[i].getHostAddress();return ips;}catch(UnknownHostException e){return new String[0];}}
        };
        worker=new Thread(()->{int result=NativeCore.runTun(path,fd,hooks);report("CORE_RETURNED",result);try{lifecycle.execute(()->{if(disconnected||token!=generation)return;worker=null;long delay=Math.min(30000,1000L<<Math.min(retry++,5));lifecycle.schedule(()->{if(!disconnected&&token==generation&&underlying!=null)restart();},delay,TimeUnit.MILLISECONDS);});}catch(RejectedExecutionException ignored){/* Destroy has already scheduled a join. */}},"vpn-core-native-tun");worker.start();
    }
    private void disconnect(){
        disconnected=true;stopWorker();if(tun!=null){try{tun.close();}catch(IOException ignored){}tun=null;}underlying=null;setUnderlyingNetworks(null);stopForeground(true);report("DISCONNECTED",0);
    }
    @Override public void onRevoke(){lifecycle.execute(()->{disconnect();stopSelf();});}
    @Override public void onDestroy(){
        connectivity.unregisterNetworkCallback(callback);lifecycle.execute(this::disconnect);lifecycle.shutdown();super.onDestroy();
    }
}
