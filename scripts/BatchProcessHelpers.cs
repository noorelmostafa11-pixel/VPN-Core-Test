// Copyright (c) 2026 Vpn project owner (noorelmostafa11-pixel). See NOTICE.md.
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace VpnBatch
{
    // These delegates run outside PowerShell runspaces. Dedicated readers keep
    // pipe draining independent of the CLR pool and async file-I/O completions.
    public static class ProcessOutput
    {
        public static Task<long> Copy(Stream input, Stream output)
        {
            return Task.Factory.StartNew<long>(() => {
                byte[] buffer = new byte[16384];
                long count = 0;
                int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) != 0)
                {
                    output.Write(buffer, 0, read);
                    count += read;
                }
                output.Flush();
                return count;
            }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        }
    }
}
