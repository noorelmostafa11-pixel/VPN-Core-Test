using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using VpnCoreSdk;
class Program {
    static byte[] Exact(NetworkStream stream,int length) {
        byte[] data=new byte[length];int offset=0;
        while(offset<length){int n=stream.Read(data,offset,length-offset);if(n==0)throw new Exception("short reply");offset+=n;}return data;
    }
    static async Task Main(string[] args) {
        if(VpnCore.AbiVersion!=2||string.IsNullOrEmpty(VpnCore.Version))throw new Exception("ABI");
        for(int index=0;index<2;index++) {
            int protects=0,resolves=0;
            var worker=Task.Run(()=>VpnCore.Run(args[0],fd=>{Interlocked.Increment(ref protects);throw new Exception("reject");},
                host=>{Interlocked.Increment(ref resolves);if(host!="bootstrap.invalid")throw new Exception("host");return new[]{IPAddress.Loopback};}));
            try {
                var end=DateTime.UtcNow.AddSeconds(5);
                while(VpnCore.State!=2&&!worker.IsCompleted&&DateTime.UtcNow<end)await Task.Delay(10);
                if(VpnCore.State!=2||VpnCore.ListenPort==0)throw new Exception("readiness");
                if(VpnCore.Run(args[0])!=2)throw new Exception("single run");
                using var client=new TcpClient("127.0.0.1",VpnCore.ListenPort);var stream=client.GetStream();stream.ReadTimeout=3000;
                stream.Write(new byte[]{5,1,0});Exact(stream,2);stream.Write(new byte[]{5,1,0,1,127,0,0,1,0,80});
                if(Exact(stream,10)[1]!=1||protects!=1||resolves!=1)throw new Exception("callbacks");
                string? error=null;var deadline=DateTime.UtcNow.AddSeconds(1);
                while(error==null&&DateTime.UtcNow<deadline){error=VpnCore.ReadEvent();if(error==null)await Task.Delay(5);}
                if(error==null||!error.Contains("SOCKET_PROTECTION_FAILED")||error.Contains("bootstrap.invalid"))throw new Exception("error API");
            } finally {VpnCore.Stop();}
            if(await worker.WaitAsync(TimeSpan.FromSeconds(5))!=0||VpnCore.State!=0||VpnCore.ListenPort!=0||VpnCore.PendingCallbacks!=0)throw new Exception("shutdown");
        }
        Console.WriteLine("PASS: .NET API lifecycle, exception rejection, UTF-8 path, callback lifetime and restart");
    }
}
