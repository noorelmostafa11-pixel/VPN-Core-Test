import com.noorelmostafa.vpncore.NativeCore;
import java.net.Socket;
import java.io.InputStream;
import java.util.concurrent.atomic.AtomicInteger;

public class SdkSmoke {
    static byte[] exact(InputStream input,int size) throws Exception {
        byte[] data=new byte[size];int offset=0;
        while(offset<size){int n=input.read(data,offset,size-offset);if(n<0)throw new Exception("short SOCKS reply");offset+=n;}return data;
    }
    public static void main(String[] args) throws Exception {
        if(NativeCore.abiVersion()!=2||NativeCore.version().isEmpty())throw new Exception("ABI");
        for(int i=0;i<2;i++) {
            AtomicInteger protects=new AtomicInteger(),resolves=new AtomicInteger(),result=new AtomicInteger(-1);
            NativeCore.NetworkHooks hooks=new NativeCore.NetworkHooks(){
                public boolean protect(int fd){protects.incrementAndGet();if(fd<0)throw new AssertionError("fd");throw new IllegalStateException("synthetic rejection");}
                public String[] resolve(String host){resolves.incrementAndGet();if(!host.equals("bootstrap.invalid"))throw new AssertionError("host");return new String[]{"127.0.0.1"};}
            };
            Thread worker=new Thread(()->result.set(NativeCore.run(args[0],hooks)));worker.start();
            try {
                long end=System.nanoTime()+5_000_000_000L;
                while(NativeCore.state()!=NativeCore.RUNNING&&worker.isAlive()&&System.nanoTime()<end)Thread.sleep(10);
                if(NativeCore.state()!=NativeCore.RUNNING||NativeCore.listenPort()==0)throw new Exception("readiness");
                if(NativeCore.run(args[0],hooks)!=2)throw new Exception("single run");
                try(Socket socket=new Socket("127.0.0.1",NativeCore.listenPort())) {
                    socket.setSoTimeout(3000);socket.getOutputStream().write(new byte[]{5,1,0});exact(socket.getInputStream(),2);
                    socket.getOutputStream().write(new byte[]{5,1,0,1,127,0,0,1,0,80});
                    if(exact(socket.getInputStream(),10)[1]!=1)throw new Exception("protection bypass");
                }
                if(protects.get()!=1||resolves.get()!=1)throw new Exception("callbacks");
            } finally {NativeCore.stop();worker.join(5000);}
            if(worker.isAlive()||result.get()!=0||NativeCore.state()!=NativeCore.STOPPED||NativeCore.listenPort()!=0)throw new Exception("shutdown");
        }
        System.out.println("PASS: Java/JNI lifecycle, UTF-8 configuration path, exception rejection, callbacks and restart");
    }
}
