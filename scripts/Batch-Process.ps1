# Process lifecycle shared by inventory inspection and batch worker runspaces.
# Windows PowerShell 5.1 / .NET Framework 4.5+ and PowerShell 7.
if (-not ('VpnBatch.ProcessOutput' -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot 'BatchProcessHelpers.cs') -ErrorAction Stop
}
function Read-BatchDiagnostic {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    foreach ($line in (Read-BatchOutput $Path).Split("`n")) {
        if ($line.Length -gt 8192 -or $line -notmatch '^\[connection ([0-9]+)\] diagnostic=(\{.*\})\s*$') { continue }
        try {
            $connectionId = [uint64]$Matches[1]
            $value = $Matches[2] | ConvertFrom-Json
            if ($value.event -notin @('failure','negotiated')) { continue }
            $safe = [ordered]@{event=$value.event;connection_id=$connectionId;timestamp_unix_ms=$null;tls_version='';alpn='';phase='';reason_code='';native_status=0;native_status_hex='';http_status=0;http_header_name='';tunnel_ready=$null}
            if ($value.PSObject.Properties['tunnel_ready'] -and $value.tunnel_ready -is [bool]) { $safe.tunnel_ready=$value.tunnel_ready }
            if ($value.PSObject.Properties['timestamp_unix_ms'] -and [string]$value.timestamp_unix_ms -match '^[0-9]{1,16}$') { $safe.timestamp_unix_ms=[uint64]$value.timestamp_unix_ms }
            if ($value.tls_version -match '^TLS(?:v)?1\.[23]$') { $safe.tls_version=$value.tls_version }
            if ($value.alpn -in @('h2','http/1.1','h3','')) { $safe.alpn=$value.alpn } else { $safe.alpn='OTHER' }
            if ($value.PSObject.Properties['http_header_name'] -and $value.http_header_name -in @('host','content-length','transfer-encoding','sec-websocket-accept','sec-websocket-protocol','sec-websocket-extensions','upgrade','server','content-type','content-encoding','other')) { $safe.http_header_name=$value.http_header_name }
            if ($value.event -eq 'failure') {
                if ($value.phase -notmatch '^[A-Z_]{1,64}$' -or $value.reason_code -notmatch '^[A-Z0-9_]{1,64}$') { continue }
                $safe.phase=$value.phase; $safe.reason_code=$value.reason_code
                $native=[uint32]$value.native_status; $http=[int]$value.http_status
                if ($http -ne 0 -and ($http -lt 100 -or $http -gt 599)) { continue }
                $safe.native_status=$native; $safe.native_status_hex='0x'+$native.ToString('X8'); $safe.http_status=$http
            }
            [pscustomobject]$safe
        } catch { continue }
    }
}
function Read-BatchOutput {
    param([string]$Path)
    # On Windows a reader must permit the already-open writer's access too.
    $stream = New-Object IO.FileStream($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    $reader = $null
    try {
        $reader = New-Object IO.StreamReader($stream,(New-Object Text.UTF8Encoding($false)),$true)
        return $reader.ReadToEnd()
    } finally {
        if ($reader) { $reader.Dispose() } else { $stream.Dispose() }
    }
}

function Read-BatchReadyState {
    param([string]$Path,$Process,[Diagnostics.Stopwatch]$Startup,[int]$TimeoutMilliseconds=10000)
    # File existence does not guarantee an immediate readable handle on Windows.
    # Retry only transient IO errors, within the original startup deadline.
    while ($true) {
        try { return ([IO.File]::ReadAllText($Path) | ConvertFrom-Json) }
        catch [IO.IOException] {
            if ($Startup.ElapsedMilliseconds -ge $TimeoutMilliseconds -or $Process.HasExited) { throw }
            Start-Sleep -Milliseconds 30
        }
    }
}

function Start-BatchChild {
    param([string]$FilePath,[string]$Arguments,[string]$Stdout,[string]$Stderr,$Owned)
    $process = New-Object Diagnostics.Process
    $outputFile = $null; $errorFile = $null; $child = $null
    try {
        # Buffer size 1 makes short, live core logs visible without waiting for exit.
        $outputFile = New-Object IO.FileStream($Stdout,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read,1,$false)
        $errorFile = New-Object IO.FileStream($Stderr,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read,1,$false)
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = $FilePath
        $info.Arguments = $Arguments
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $process.StartInfo = $info
        if (-not $process.Start()) { throw 'Child process did not start.' }
        # This Process instance starts and owns the native handle itself.
        $handle = $process.Handle
        [void]$Owned.TryAdd($process.Id,$process)
        $child = [pscustomobject]@{Process=$process;Id=$process.Id;Handle=$handle;StdoutFile=$outputFile;StderrFile=$errorFile;StdoutTask=$null;StderrTask=$null;Closed=$false}
        # Drain both pipes immediately and concurrently; never wait with full pipes.
        # Copy raw UTF-8 bytes without PowerShell's text decoding/re-encoding.
        $child.StdoutTask = [VpnBatch.ProcessOutput]::Copy($process.StandardOutput.BaseStream,$outputFile)
        $child.StderrTask = [VpnBatch.ProcessOutput]::Copy($process.StandardError.BaseStream,$errorFile)
        return $child
    } catch {
        if ($child) { Stop-BatchChild $child $Owned }
        else {
            try {
                if ($process.Id -gt 0) {
                    if (-not $process.HasExited) { $process.Kill() }
                    [void]$process.WaitForExit(3000)
                    $removed = $null; [void]$Owned.TryRemove($process.Id,[ref]$removed)
                }
            } catch {}
            if ($outputFile) { $outputFile.Dispose() }
            if ($errorFile) { $errorFile.Dispose() }
            $process.Dispose()
        }
        throw
    }
}

function Wait-BatchChild {
    param($Child,[int]$TimeoutMilliseconds,[ValidateRange(0,120000)][int]$OutputDrainMilliseconds=10000)
    $finished = $Child.Process.WaitForExit($TimeoutMilliseconds)
    $reason = ''; $exitCode = $null; $outputComplete = $false
    $drain = [Diagnostics.Stopwatch]::StartNew(); $drain.Stop()
    if (-not $finished) {
        $reason = 'TIMEOUT'
        try { $Child.Process.Kill() } catch {}
        [void]$Child.Process.WaitForExit(3000)
    }
    if ($Child.Process.HasExited) {
        try {
            # Invoke the .NET getter explicitly: getter failures must throw, not
            # become a null PowerShell property value that could be cast to zero.
            $exitCode = ([Diagnostics.Process]).GetProperty('ExitCode').GetValue($Child.Process,$null)
            if ($null -eq $exitCode -and -not $reason) { $reason = 'EXIT_CODE_UNAVAILABLE' }
        } catch { if (-not $reason) { $reason = 'EXIT_CODE_QUERY_FAILED' } }
        try {
            $tasks = [Threading.Tasks.Task[]]@($Child.StdoutTask,$Child.StderrTask)
            $drain.Start()
            $outputComplete = [Threading.Tasks.Task]::WaitAll($tasks,$OutputDrainMilliseconds)
            $drain.Stop()
            if ($outputComplete) { $Child.StdoutFile.Flush(); $Child.StderrFile.Flush() }
            elseif (-not $reason) { $reason = 'OUTPUT_DRAIN_TIMEOUT' }
        } catch { if (-not $reason) { $reason = 'OUTPUT_CAPTURE_FAILED' } }
        finally { $drain.Stop() }
    }
    return [pscustomobject]@{Finished=$finished;OutputComplete=$outputComplete;ExitCode=$exitCode;Reason=$reason;DrainTimeoutMilliseconds=$OutputDrainMilliseconds;DrainMilliseconds=[Math]::Round($drain.Elapsed.TotalMilliseconds,3);StdoutBytes=$Child.StdoutFile.Length;StderrBytes=$Child.StderrFile.Length;StdoutState=$Child.StdoutTask.Status.ToString();StderrState=$Child.StderrTask.Status.ToString()}
}

function Stop-BatchChild {
    param($Child,$Owned)
    if ($null -eq $Child -or $Child.Closed) { return }
    try {
        if (-not $Child.Process.HasExited) { $Child.Process.Kill() }
        [void]$Child.Process.WaitForExit(3000)
        $tasks = [Threading.Tasks.Task[]]@(@($Child.StdoutTask,$Child.StderrTask) | Where-Object { $null -ne $_ })
        if ($tasks.Count) { [void][Threading.Tasks.Task]::WaitAll($tasks,3000) }
    } catch {}
    finally {
        # Closing read pipes also releases a copy task if a child kept them open.
        try { $Child.Process.StandardOutput.Dispose() } catch {}
        try { $Child.Process.StandardError.Dispose() } catch {}
        try { $Child.StdoutFile.Dispose() } catch {}
        try { $Child.StderrFile.Dispose() } catch {}
        $removed = $null; [void]$Owned.TryRemove($Child.Id,[ref]$removed)
        $Child.Process.Dispose()
        $Child.Closed = $true
    }
}

# Stable curl classes. Raw error text is never copied into a report.
function Get-BatchCurlClass($ExitCode) {
    if ($null -eq $ExitCode) { return 'CURL_EXIT_UNAVAILABLE' }
    switch ([int]$ExitCode) {
        0 {'CURL_OK'} 5 {'CURL_PROXY_DNS'} 6 {'CURL_DESTINATION_DNS'}
        7 {'CURL_PROXY_CONNECT'} 22 {'HTTPS_HTTP_STATUS'} 28 {'CURL_TIMEOUT'}
        35 {'HTTPS_TLS_HANDSHAKE'} 51 {'HTTPS_CERTIFICATE'} 60 {'HTTPS_CERTIFICATE'}
        77 {'HTTPS_CA_FILE'} 83 {'HTTPS_CERTIFICATE_ISSUER'} 90 {'HTTPS_CERTIFICATE_PIN'}
        91 {'HTTPS_CERTIFICATE_STATUS'} 52 {'HTTPS_EMPTY_REPLY'} 56 {'CURL_RECEIVE'}
        97 {'SOCKS_NEGOTIATION'} default {'CURL_OTHER'}
    }
}
