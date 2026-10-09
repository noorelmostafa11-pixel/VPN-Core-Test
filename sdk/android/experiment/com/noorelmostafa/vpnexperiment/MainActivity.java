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

/** Experimental host, not a replacement protocol engine. */
public final class MainActivity extends Activity {
    private TextView status;private EditText uri;private String config;
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
            try{copyAsset("node.ini",new File(config));copyAsset("ca.pem",new File(getFilesDir(),"ca.pem"));String value=new String(read(new File(config)),StandardCharsets.UTF_8).replace("@CA@",new File(getFilesDir(),"ca.pem").getAbsolutePath()).replace("@PORT@",Integer.toString(getIntent().getIntExtra("peer_port",0))).replace("@TRANSPORT@",getIntent().getStringExtra("transport")==null?"raw":getIntent().getStringExtra("transport"));try(FileOutputStream out=new FileOutputStream(config)){out.write(value.getBytes(StandardCharsets.UTF_8));}consent();new Thread(this::fixture,"vpn-fixture").start();}catch(Exception e){fixtureReport("FAIL: fixture setup");}
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
        for(int i=0;i<targets.length;i++){long remaining=(deadline-System.nanoTime())/1000000L;if(remaining<=0)break;int budget=(int)Math.max(1,remaining/(targets.length-i));HttpURLConnection request=null;
            try{request=(HttpURLConnection)new URL(targets[i]).openConnection();request.setInstanceFollowRedirects(false);request.setConnectTimeout(budget);request.setReadTimeout(budget);int code=request.getResponseCode();if(code>=200&&code<300){success=true;break;}}catch(IOException ignored){}finally{if(request!=null)request.disconnect();}}
        show(success?"PASS: validated HTTP response through native tunnel":"FAIL: no validated response within total deadline");
    }
    private void fixtureReport(String text){try(FileOutputStream out=new FileOutputStream(new File(getFilesDir(),"fixture-report.txt"))){out.write(text.getBytes(StandardCharsets.UTF_8));}catch(IOException ignored){}android.util.Log.i("VpnTunFixture",text);show(text);}
    private static byte[] exact(InputStream in,int n)throws IOException{byte[] b=new byte[n];int pos=0,count;while(pos<n&&(count=in.read(b,pos,n-pos))>0)pos+=count;if(pos!=n)throw new EOFException();return b;}
    private void fixture(){
        try{
            long deadline=System.nanoTime()+30000000000L;while(!NativeCore.tunReady()){if(System.nanoTime()>deadline)throw new IOException("TUN startup timeout");Thread.sleep(20);}
            for(String destination:new String[]{"203.0.113.9","2001:db8::9"}){
                try(Socket socket=new Socket()){socket.connect(new InetSocketAddress(destination,443),5000);socket.setSoTimeout(5000);InputStream in=socket.getInputStream();byte[] hello="SERVER-FIRST: independent peer\n".getBytes(StandardCharsets.UTF_8);if(!Arrays.equals(hello,exact(in,hello.length)))throw new IOException("TCP greeting");byte[] data=new byte[65536];for(int i=0;i<data.length;i++)data[i]=(byte)(i*17);socket.getOutputStream().write(data);if(!Arrays.equals(data,exact(in,data.length)))throw new IOException("TCP data");}
                try(DatagramSocket socket=new DatagramSocket()){socket.setSoTimeout(5000);for(int size:new int[]{0,1,512,1200}){byte[] data=new byte[size];Arrays.fill(data,(byte)size);socket.send(new DatagramPacket(data,data.length,InetAddress.getByName(destination),443));DatagramPacket reply=new DatagramPacket(new byte[65535],65535);socket.receive(reply);if(reply.getLength()!=size||!Arrays.equals(data,Arrays.copyOf(reply.getData(),size)))throw new IOException("UDP record");}}
            }
            fixtureReport("PASS: actual VpnService JNI FD TCP UDP IPv4 IPv6 encrypted peer");
            startService(new Intent(this,VpnCoreVpnService.class).setAction(VpnCoreVpnService.DISCONNECT));
        }catch(Exception e){fixtureReport("FAIL: "+e.getClass().getSimpleName()+": "+e.getMessage());}
    }
}
