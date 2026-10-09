package com.noorelmostafa.vpnexperiment;
import android.app.*;
import android.content.*;
import android.net.VpnService;
import android.os.*;
import android.widget.*;
import com.noorelmostafa.vpncore.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import org.json.*;

/** Experimental host, not a replacement protocol engine. */
public final class MainActivity extends Activity {
    private TextView status;private EditText uri;private String config;private Thread proxyWorker;
    private final ThreadPoolExecutor http=new ThreadPoolExecutor(3,3,0,TimeUnit.SECONDS,new ArrayBlockingQueue<Runnable>(3));
    @Override public void onCreate(Bundle saved){
        super.onCreate(saved);LinearLayout panel=new LinearLayout(this);panel.setOrientation(LinearLayout.VERTICAL);
        uri=new EditText(this);uri.setHint("Original node URI");uri.setSingleLine(true);panel.addView(uri);
        Button connect=new Button(this);connect.setText("Connect Native TUN");panel.addView(connect);
        Button disconnect=new Button(this);disconnect.setText("Disconnect");panel.addView(disconnect);
        Button test=new Button(this);test.setText("Test HTTPS connection");panel.addView(test);
        status=new TextView(this);panel.addView(status);setContentView(panel);
        config=new File(getFilesDir(),"node.ini").getAbsolutePath();
        connect.setOnClickListener(v->{try{writeConfig();consent();}catch(Exception e){show("Configuration failed");}});
        disconnect.setOnClickListener(v->{startService(new Intent(this,VpnCoreVpnService.class).setAction(VpnCoreVpnService.DISCONNECT));show("Disconnect requested");});
        test.setOnClickListener(v->new Thread(this::testInternet,"vpn-test").start());
        if(getIntent().getBooleanExtra("fixture",false)){
            try{copyAsset("node.ini",new File(config));copyAsset("ca.pem",new File(getFilesDir(),"ca.pem"));String value=new String(read(new File(config)),StandardCharsets.UTF_8).replace("@CA@",new File(getFilesDir(),"ca.pem").getAbsolutePath()).replace("@PORT@",Integer.toString(getIntent().getIntExtra("peer_port",0))).replace("@TRANSPORT@",getIntent().getStringExtra("transport")==null?"raw":getIntent().getStringExtra("transport"));if(getIntent().getBooleanExtra("bad_certificate",false))value=value.replace("sni=localhost","sni=wrong.invalid");try(FileOutputStream out=new FileOutputStream(config)){out.write(value.getBytes(StandardCharsets.UTF_8));}if(getIntent().getBooleanExtra("proxy",false)){proxyWorker=new Thread(()->NativeCore.runStandalone(config),"vpn-core-proxy-benchmark");proxyWorker.start();}else consent();new Thread(this::fixture,"vpn-fixture").start();}catch(Exception e){fixtureReport("FAIL: fixture setup");}
        }
    }
    private static byte[] read(File f)throws IOException{try(FileInputStream in=new FileInputStream(f)){ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] b=new byte[4096];int n;while((n=in.read(b))>0)out.write(b,0,n);return out.toByteArray();}}
    private void copyAsset(String asset,File destination)throws IOException{try(InputStream in=getAssets().open(asset);FileOutputStream out=new FileOutputStream(destination)){byte[] b=new byte[4096];int n;while((n=in.read(b))>0)out.write(b,0,n);}}
    private void writeConfig()throws IOException{String original=uri.getText().toString();if(original.indexOf('\n')>=0||original.indexOf('\r')>=0)throw new IOException("URI newline");try(FileOutputStream out=new FileOutputStream(config)){out.write(("node_uri="+original+"\nconnect_timeout_ms=10000\nidle_timeout_ms=60000\nmax_connections=64\n").getBytes(StandardCharsets.UTF_8));}}
    private void consent(){Intent approval=VpnService.prepare(this);if(approval!=null)startActivityForResult(approval,1);else connect();}
    @Override protected void onActivityResult(int request,int result,Intent data){super.onActivityResult(request,result,data);if(request==1&&result==RESULT_OK)connect();}
    private void connect(){Intent intent=new Intent(this,VpnCoreVpnService.class).setAction(VpnCoreVpnService.CONNECT).putExtra(VpnCoreVpnService.CONFIG,config);if(Build.VERSION.SDK_INT>=26)startForegroundService(intent);else startService(intent);show("Connecting; readiness does not prove node connectivity");}
    private void show(String text){runOnUiThread(()->status.setText(text));}
    private void testInternet(){
        String[] targets={"https://example.com/","http://connectivitycheck.gstatic.com/generate_204","https://www.microsoft.com/robots.txt"};long deadline=System.nanoTime()+10000000000L;boolean success=false;
        for(int i=0;i<targets.length;i++){
            long remaining=(deadline-System.nanoTime())/1000000L;if(remaining<=0)break;
            int budget=(int)Math.max(1,remaining/(targets.length-i));final String target=targets[i];AtomicReference<HttpURLConnection> current=new AtomicReference<>();Future<Integer> task=null;
            try{
                task=http.submit(()->{HttpURLConnection request=(HttpURLConnection)new URL(target).openConnection();current.set(request);try{request.setInstanceFollowRedirects(false);request.setConnectTimeout(budget);request.setReadTimeout(budget);return request.getResponseCode();}finally{request.disconnect();}});
                int code=task.get(Math.min(budget,Math.max(1,(deadline-System.nanoTime())/1000000L)),TimeUnit.MILLISECONDS);
                if(code>=200&&code<300){success=true;break;}
            }catch(Exception ignored){}finally{if(task!=null)task.cancel(true);HttpURLConnection request=current.get();if(request!=null)request.disconnect();}
        }
        show(success?"PASS: validated HTTP response through native tunnel":"FAIL: no validated response within total deadline");
    }
    private void fixtureReport(String text){try(FileOutputStream out=new FileOutputStream(new File(getFilesDir(),"fixture-report.txt"))){out.write(text.getBytes(StandardCharsets.UTF_8));}catch(IOException ignored){}android.util.Log.i("VpnTunFixture",text);show(text);}
    private static byte[] exact(InputStream in,int n)throws IOException{byte[] b=new byte[n];int pos=0,count;while(pos<n&&(count=in.read(b,pos,n-pos))>0)pos+=count;if(pos!=n)throw new EOFException();return b;}
    private Socket benchmarkSocket()throws Exception {
        Socket socket=new Socket();
        try {
            socket.connect(new InetSocketAddress(proxyWorker==null?"203.0.113.9":"127.0.0.1",proxyWorker==null?443:NativeCore.listenPort()),10000);socket.setSoTimeout(30000);
            if(proxyWorker!=null){
                socket.getOutputStream().write(new byte[]{5,1,0});if(!Arrays.equals(exact(socket.getInputStream(),2),new byte[]{5,0}))throw new IOException("SOCKS greeting");
                socket.getOutputStream().write(new byte[]{5,1,0,1,(byte)203,0,113,9,1,(byte)187});if(exact(socket.getInputStream(),10)[1]!=0)throw new IOException("SOCKS request");
            }
            byte[] hello="SERVER-FIRST: independent peer\n".getBytes(StandardCharsets.UTF_8);
            if(!Arrays.equals(exact(socket.getInputStream(),hello.length),hello))throw new IOException("Benchmark greeting");return socket;
        }catch(Exception e){socket.close();throw e;}
    }
    private JSONObject workload(int bytes)throws Exception {
        try(Socket socket=benchmarkSocket()){
            long[] rtt=new long[100];byte[] request=new byte[512];
            for(int i=0;i<rtt.length;i++){Arrays.fill(request,(byte)i);long start=System.nanoTime();socket.getOutputStream().write(request);if(!Arrays.equals(request,exact(socket.getInputStream(),512)))throw new IOException("RTT payload");rtt[i]=System.nanoTime()-start;}
            byte[] block=new byte[65536];for(int i=0;i<block.length;i++)block[i]=(byte)i;
            final Exception[] error=new Exception[1];long start=System.nanoTime();boolean complete=false;
            Thread sender=new Thread(()->{try{for(int i=0;i<bytes/block.length;i++)socket.getOutputStream().write(block);}catch(Exception e){error[0]=e;}},"benchmark-upload");sender.start();
            try{for(int i=0;i<bytes/block.length;i++)if(!Arrays.equals(block,exact(socket.getInputStream(),block.length)))throw new IOException("Throughput payload");complete=true;}
            finally{if(!complete)socket.close();sender.join(30000);if(sender.isAlive()){socket.close();sender.join();throw new IOException("Benchmark writer timeout");}}
            if(error[0]!=null)throw error[0];double seconds=(System.nanoTime()-start)/1e9;Arrays.sort(rtt);
            return new JSONObject().put("status","PASS").put("verified_payload_bytes",bytes).put("elapsed_seconds",seconds).put("goodput_mbit_s",bytes*8/seconds/1e6).put("rtt_ms_p50",(rtt[49]+rtt[50])/2e6).put("rtt_ms_p95",rtt[94]/1e6).put("rtt_ms_p99",rtt[98]/1e6);
        }
    }
    private void stopFixture()throws Exception {
        if(proxyWorker!=null){NativeCore.stop();proxyWorker.join(15000);if(proxyWorker.isAlive())throw new IOException("Proxy join timeout");}
        else {
            startService(new Intent(this,VpnCoreVpnService.class).setAction(VpnCoreVpnService.DISCONNECT));
            long deadline=System.nanoTime()+15000000000L;
            while(NativeCore.state()!=NativeCore.STOPPED){if(System.nanoTime()>deadline)throw new IOException("TUN stop timeout");Thread.sleep(20);}
        }
        if(NativeCore.pendingCallbacks()!=0)throw new IOException("Undrained callbacks");
    }
    private void verifyNetworkPolicy()throws Exception {
        android.net.ConnectivityManager manager=(android.net.ConnectivityManager)getSystemService(CONNECTIVITY_SERVICE);
        long deadline=System.nanoTime()+5000000000L;
        while(System.nanoTime()<deadline){
            for(android.net.Network network:manager.getAllNetworks()){
                android.net.NetworkCapabilities cap=manager.getNetworkCapabilities(network);
                if(cap==null||!cap.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN))continue;
                android.net.LinkProperties link=manager.getLinkProperties(network);if(link==null)continue;
                boolean v4=false,v6=false,dns4=false,dns6=false;
                for(android.net.RouteInfo route:link.getRoutes())if(route.getDestination().getPrefixLength()==0){if(route.getDestination().getAddress() instanceof Inet6Address)v6=true;else v4=true;}
                for(InetAddress dns:link.getDnsServers()){if(dns instanceof Inet6Address)dns6=true;else dns4=true;}
                if(v4&&v6&&dns4&&dns6){android.util.Log.i("VpnTunFixture","PASS: system VPN IPv4 IPv6 default routes and link DNS");return;}
            }
            Thread.sleep(20);
        }
        throw new IOException("System VPN routes/DNS missing");
    }
    private void benchmark()throws Exception {
        workload(1024*1024);long cpu=android.os.Process.getElapsedCpuTime();JSONObject result=workload(8*1024*1024);
        result.put("cpu_seconds",(android.os.Process.getElapsedCpuTime()-cpu)/1000.0);
        Debug.MemoryInfo memory=new Debug.MemoryInfo();Debug.getMemoryInfo(memory);result.put("pss_bytes",memory.getTotalPss()*1024L);
        for(String line:new String(read(new File("/proc/self/status")),StandardCharsets.UTF_8).split("\n")){
            if(line.startsWith("VmRSS:"))result.put("rss_bytes",Long.parseLong(line.trim().split("\\s+")[1])*1024L);
            if(line.startsWith("VmHWM:"))result.put("peak_rss_bytes",Long.parseLong(line.trim().split("\\s+")[1])*1024L);
        }
        stopFixture();JSONArray events=new JSONArray();String event;
        while((event=NativeCore.readEvent())!=null){JSONObject value=new JSONObject(event);if("tun_metrics".equals(value.optString("event")))events.put(value);}
        result.put("native_abi_metrics_including_warmup",events);
        try(FileOutputStream out=new FileOutputStream(new File(getFilesDir(),"benchmark-report.json"))){out.write(result.toString().getBytes(StandardCharsets.UTF_8));}
        fixtureReport("PASS: equivalent encrypted benchmark");
    }
    private void fixture(){
        String stage="startup";
        try{
            long deadline=System.nanoTime()+30000000000L;while(proxyWorker==null?!NativeCore.tunReady():NativeCore.listenPort()==0){if(System.nanoTime()>deadline)throw new IOException("TUN startup timeout");Thread.sleep(20);}
            if(proxyWorker==null)verifyNetworkPolicy();
            if(getIntent().getBooleanExtra("benchmark",false)){benchmark();return;}
            if(getIntent().getBooleanExtra("bad_certificate",false)){
                boolean rejected=false;
                try(Socket socket=benchmarkSocket()){socket.getOutputStream().write(1);}catch(IOException expected){rejected=true;}
                if(!rejected||!NativeCore.tunReady())throw new IOException("Invalid certificate did not fail closed");
                stopFixture();fixtureReport("PASS: invalid certificate rejected; TUN retained until explicit disconnect");return;
            }
            for(String destination:new String[]{"203.0.113.9","2001:db8::9"}){
                stage="TCP "+destination;android.util.Log.i("VpnTunFixture",stage);
                try(Socket socket=new Socket()){socket.connect(new InetSocketAddress(destination,443),5000);socket.setSoTimeout(5000);InputStream in=socket.getInputStream();byte[] hello="SERVER-FIRST: independent peer\n".getBytes(StandardCharsets.UTF_8);if(!Arrays.equals(hello,exact(in,hello.length)))throw new IOException("TCP greeting");byte[] data=new byte[65536];for(int i=0;i<data.length;i++)data[i]=(byte)(i*17);socket.getOutputStream().write(data);if(!Arrays.equals(data,exact(in,data.length)))throw new IOException("TCP data");}
                stage="UDP "+destination;android.util.Log.i("VpnTunFixture",stage);
                try(DatagramSocket socket=new DatagramSocket()){socket.setSoTimeout(5000);for(int size:new int[]{0,1,512,1200}){byte[] data=new byte[size];Arrays.fill(data,(byte)size);socket.send(new DatagramPacket(data,data.length,InetAddress.getByName(destination),443));DatagramPacket reply=new DatagramPacket(new byte[65535],65535);socket.receive(reply);if(reply.getLength()!=size||!Arrays.equals(data,Arrays.copyOf(reply.getData(),size)))throw new IOException("UDP record");}}
            }
            stopFixture();fixtureReport("PASS: actual VpnService JNI FD TCP UDP IPv4 IPv6 encrypted peer; joined cleanly");
        }catch(Exception e){String event;while((event=NativeCore.readEvent())!=null)android.util.Log.i("VpnTunFixture",event);fixtureReport("FAIL: "+stage+": "+e.getClass().getSimpleName()+": "+e.getMessage());}
    }
    @Override protected void onDestroy(){http.shutdownNow();super.onDestroy();}
}
