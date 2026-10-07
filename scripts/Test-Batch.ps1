param(
    [string]$Nodes = (Join-Path (Split-Path $PSScriptRoot -Parent) 'nodes\pre\protocols'),
    [string]$Core = (Join-Path (Split-Path $PSScriptRoot -Parent) 'bin\vpn-core.exe'),
    [string]$Curl = 'curl.exe',
    [ValidateRange(1,32)][int]$Concurrency = 8,
    [ValidateRange(0,100000)][int]$Limit = 0,
    [ValidateRange(1,120)][int]$TimeoutSeconds = 20,
    [string]$Url = 'https://example.com/',
    [string]$ExpectedBodySha256 = '',
    [string]$OutputDirectory = '',
    [string]$TestCaFile = '',
    [switch]$InspectOnly
)
# Windows PowerShell 5.1 / PowerShell 7. No Python dependency.
# Batch script revision 0.4.2: retain only whitelisted structured diagnostics.
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$processHelper = Join-Path $PSScriptRoot 'Batch-Process.ps1'
. $processHelper
if (-not ([uri]$Url).IsAbsoluteUri -or ([uri]$Url).Scheme -ne 'https' -or ([uri]$Url).UserInfo) { throw 'Url must use HTTPS.' }
if ($ExpectedBodySha256 -and $ExpectedBodySha256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'ExpectedBodySha256 must contain 64 hex characters.' }
$Core = (Resolve-Path -LiteralPath $Core).Path
$Curl = (Get-Command $Curl -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
if ($TestCaFile) { $TestCaFile = (Resolve-Path -LiteralPath $TestCaFile).Path }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path (Get-Location) ('batch-results-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,6)) }
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Use a new OutputDirectory; existing reports are preserved.' }
$OutputDirectory = [IO.Directory]::CreateDirectory($OutputDirectory).FullName
$scratch = [IO.Directory]::CreateDirectory((Join-Path ([IO.Path]::GetTempPath()) ('vpn-batch-' + [guid]::NewGuid().ToString('N')))).FullName
if ($env:OS -eq 'Windows_NT') {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $scratch -AclObject $acl
}
$encoding = New-Object Text.UTF8Encoding($false)
$resultsFile = Join-Path $OutputDirectory 'results.ndjson'
$writer = New-Object IO.StreamWriter($resultsFile,$false,$encoding)
$writer.AutoFlush = $true
$results = New-Object Collections.Generic.List[object]
$scheduled = New-Object Collections.Generic.HashSet[string]
$owned = New-Object 'Collections.Concurrent.ConcurrentDictionary[int,System.Diagnostics.Process]'
$jobs = New-Object Collections.Generic.List[object]
$pool = $null
$catalog = New-Object Collections.Generic.List[object]
$sourceHashes = New-Object Collections.Generic.List[object]
$selectedCount = 0
$completed = $false
$inventoryError = $null
$inspectionChild = $null
function Get-ReportCause($Row,[string]$Key,[string]$Field) {
    if ($Row.PSObject.Properties[$Key] -and $Row.$Key -and $Row.$Key.PSObject.Properties[$Field]) { return $Row.$Key.$Field }
    return $null
}
function Save-Row($row) {
    $results.Add($row)
    $writer.WriteLine(($row | ConvertTo-Json -Depth 12 -Compress))
}
$worker = {
    param($item,$corePath,$curlPath,$urlValue,$timeoutValue,$expectedHash,$tempRoot,$processes,$caFile,$helperPath)
    $ErrorActionPreference = 'Stop'
    . $helperPath
    $dir = [IO.Directory]::CreateDirectory((Join-Path $tempRoot ([guid]::NewGuid().ToString('N')))).FullName
    $p = $null; $request = $null; $readyObserved = $false; $beforeCleanup = @()
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $r = [ordered]@{feature_family=$item.Row.feature_family;plugin=$item.Row.plugin;plugin_mux=$item.Row.plugin_mux;websocket_early_data=$item.Row.websocket_early_data;vmess_authentication=$item.Row.vmess_authentication;alter_id=$item.Row.alter_id;source=$item.Row.source;line=$item.Row.line;node_id=$item.Row.node_id;protocol=$item.Row.protocol;transport=$item.Row.transport;security=$item.Row.security;cipher=$item.Row.cipher;flow=$item.Row.flow;fingerprint=$item.Row.fingerprint;mode=$item.Row.mode;header_type=$item.Row.header_type;finalmask=$item.Row.finalmask;alpn_compatibility=$item.Row.alpn_compatibility;alpn_configuration_reason_code=$item.Row.alpn_configuration_reason_code;status='FAIL';failure_scope='RUNNER';phase='STARTUP_FAILED';runner_reason_code='';readiness_reason='';core_exit_code=$null;core_output_complete=$null;core_stopped_by_runner=$false;curl_wait_reason='';curl_output_complete=$null;curl_error_class='';first_core_failure=$null;last_core_failure=$null;core_failure_count=0;reason_code='';native_status=0;native_status_hex='';transport_http_status=0;transport_http_header_name='';negotiated_alpn='';tls_version='';network_test_performed=$false;curl_exit_code=$null;http_code=0;bytes=0;seconds=0;body_sha256='';missing_features=@()}
    try {
        $ready = Join-Path $dir 'ready.json'
        $config = Join-Path $dir 'node.ini'
        $text = "node_uri=$($item.Uri)`nlisten_port=0`nready_file=$ready`nconnect_timeout_ms=$([Math]::Min(120000,$timeoutValue*1000))`nidle_timeout_ms=$([Math]::Min(600000,$timeoutValue*1000))`nmax_connections=4`n"
        if ($caFile) { $text += "test_ca_file=$caFile`n" }
        [IO.File]::WriteAllText($config,$text,(New-Object Text.UTF8Encoding($false)))
        $out = Join-Path $dir 'core-out.log'; $err = Join-Path $dir 'core-err.log'
        # Redirection keeps native stderr outside PowerShell's error stream.
        $p = Start-BatchChild $corePath ('--config "' + $config + '"') $out $err $processes
        $startup = [Diagnostics.Stopwatch]::StartNew()
        while (-not (Test-Path -LiteralPath $ready)) {
            if ($p.Process.HasExited) { $r.readiness_reason='CORE_EXITED_BEFORE_READY'; throw 'Core exited before readiness.' }
            if ($startup.Elapsed.TotalSeconds -gt 10) { $r.readiness_reason='CORE_READY_TIMEOUT'; throw 'Core readiness timeout.' }
            Start-Sleep -Milliseconds 30
        }
        $state = [IO.File]::ReadAllText($ready) | ConvertFrom-Json
        if ($state.pid -ne $p.Id -or $state.port -lt 1 -or $p.Process.HasExited) { $r.readiness_reason='CORE_READY_IDENTITY'; throw 'Core readiness identity mismatch.' }
        $readyObserved=$true; $r.readiness_reason='CORE_READY'
        $body = Join-Path $dir 'body.bin'; $metrics = Join-Path $dir 'curl-out.txt'; $curlError = Join-Path $dir 'curl-err.txt'
        $arguments = '--silent --show-error --fail --location --proto "=https" --proto-redir "=https" --noproxy "not-used.invalid" --proxy "socks5h://127.0.0.1:' + $state.port + '" --connect-timeout ' + $timeoutValue + ' --max-time ' + $timeoutValue + ' --output "' + $body + '" --write-out "%{http_code}|%{size_download}|%{time_total}" '
        if ($caFile) { $arguments += '--cacert "' + $caFile + '" ' }
        $arguments += '"' + $urlValue.Replace('"','%22') + '"'
        $r.phase = 'HTTPS_FAILED'; $r.network_test_performed = $true
        $request = Start-BatchChild $curlPath $arguments $metrics $curlError $processes
        $requestResult = Wait-BatchChild $request (($timeoutValue+5)*1000)
        $r.curl_exit_code=$requestResult.ExitCode; $r.curl_wait_reason=$requestResult.Reason; $r.curl_output_complete=$requestResult.OutputComplete
        $r.curl_error_class=Get-BatchCurlClass $requestResult.ExitCode
        if ($requestResult.Reason) { $r.runner_reason_code=$requestResult.Reason; $r.phase = $requestResult.Reason; throw ('HTTPS process failed: '+$requestResult.Reason) }
        $curlExitCode = $requestResult.ExitCode
        if ($null -eq $curlExitCode) { $r.phase = 'EXIT_CODE_UNAVAILABLE'; throw 'Curl exit code is unavailable.' }
        $r.curl_exit_code = [int]$curlExitCode
        $values = (Read-BatchOutput $metrics).Trim().Split('|')
        if ($values.Count -eq 3) {
            $r.http_code = [int]$values[0]
            $r.bytes = [int64]([double]::Parse($values[1],[Globalization.CultureInfo]::InvariantCulture))
        }
        if (Test-Path -LiteralPath $body) { $r.body_sha256 = (Get-FileHash -LiteralPath $body -Algorithm SHA256).Hash.ToLowerInvariant() }
        if ($curlExitCode -eq 0 -and $r.http_code -eq 200 -and $r.bytes -gt 0 -and (-not $expectedHash -or $r.body_sha256 -eq $expectedHash.ToLowerInvariant())) {
            $r.status = 'PASS'; $r.phase = 'HTTPS_BODY_VERIFIED'
        } else {
            Start-Sleep -Milliseconds 50
            if ($curlExitCode -eq 28) { $r.phase = 'TIMEOUT' }
            elseif ($expectedHash -and $curlExitCode -eq 0) { $r.phase = 'BODY_HASH_MISMATCH' }

        }
    } catch {
        if ($r.readiness_reason -and -not $readyObserved) { $r.runner_reason_code=$r.readiness_reason }
        elseif (-not $r.runner_reason_code) { $r.runner_reason_code='BATCH_WORKER_FAILED' }
        if ($r.readiness_reason -eq 'CORE_READY_TIMEOUT') { $r.phase='STARTUP_FAILED' }
    } finally {
        # Snapshot causes before we terminate owned processes. Cleanup failures
        # are recorded separately and cannot replace an earlier cause.
        foreach ($path in @('core-out.log','core-err.log')) { $beforeCleanup += @(Read-BatchDiagnostic (Join-Path $dir $path)) }
        $preFailures=@($beforeCleanup | Where-Object { $_.event -eq 'failure' })
        if ($p) {
            try {
                if ($p.Process.HasExited) { $coreResult=Wait-BatchChild $p 1000; $r.core_exit_code=$coreResult.ExitCode; $r.core_output_complete=$coreResult.OutputComplete }
                else { $r.core_stopped_by_runner=$true }
            } catch { $r.core_output_complete=$false }
        }
        foreach ($child in @($request,$p)) { Stop-BatchChild $child $processes }
        $diagnostics=@()
        foreach ($path in @('core-out.log','core-err.log')) { $diagnostics += @(Read-BatchDiagnostic (Join-Path $dir $path)) }
        $failures=@($diagnostics | Where-Object { $_.event -eq 'failure' } | Sort-Object timestamp_unix_ms)
        $r.core_failure_count=$failures.Count
        if ($failures.Count) {
            $r.first_core_failure=$failures[0]; $r.last_core_failure=$failures[-1]
            $r.first_core_failure | Add-Member NoteProperty observed_before_cleanup ([bool]$preFailures.Count)
        }
        foreach ($diagnostic in $diagnostics) {
            if ($diagnostic.tls_version) { $r.tls_version=$diagnostic.tls_version }
            if ($diagnostic.alpn) { $r.negotiated_alpn=$diagnostic.alpn }
        }
        if ($r.status -eq 'FAIL' -and $preFailures.Count) {
            $first=@($preFailures | Sort-Object timestamp_unix_ms)[0]
            # Keep explicit runner/wait failure while retaining both core causes.
            if (-not $r.runner_reason_code) {
                if ($r.curl_error_class -in @('HTTPS_TLS_HANDSHAKE','HTTPS_CERTIFICATE','HTTPS_CERTIFICATE_ISSUER','HTTPS_CERTIFICATE_PIN','HTTPS_CERTIFICATE_STATUS')) { $r.phase='HTTPS_FAILED'; $r.reason_code=$r.curl_error_class; $r.failure_scope='HTTPS_DESTINATION_TLS' }
                else { $r.phase=$first.phase; $r.reason_code=$first.reason_code; $r.failure_scope='OUTER_TUNNEL' }
            }
            $r.native_status=$first.native_status; $r.native_status_hex=$first.native_status_hex; $r.transport_http_status=$first.http_status; $r.transport_http_header_name=$first.http_header_name
        }
        if ($r.status -eq 'PASS') { $r.failure_scope='NONE' }
        elseif ($r.runner_reason_code) { $r.reason_code=$r.runner_reason_code; $r.failure_scope='RUNNER' }
        elseif (-not $preFailures.Count) {
            $r.failure_scope='HTTPS_REQUEST'
            if ($r.curl_error_class -in @('HTTPS_TLS_HANDSHAKE','HTTPS_CERTIFICATE','HTTPS_CERTIFICATE_ISSUER','HTTPS_CERTIFICATE_PIN','HTTPS_CERTIFICATE_STATUS')) { $r.failure_scope='HTTPS_DESTINATION_TLS'; $r.phase='HTTPS_FAILED'; $r.reason_code=$r.curl_error_class }
            elseif ($r.curl_error_class -eq 'HTTPS_CA_FILE') { $r.failure_scope='RUNNER_CONFIGURATION'; $r.reason_code='HTTPS_CA_FILE' }
        }
        if ($r.status -eq 'FAIL' -and -not $r.reason_code) { $r.reason_code=$r.phase }
        $r.seconds = [Math]::Round($timer.Elapsed.TotalSeconds,3)
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    }
    [pscustomobject]$r
}
try {
    Write-Host 'Batch runner: 0.4.2 (direct .NET processes; structured diagnostics)'
    $files = if (Test-Path -LiteralPath $Nodes -PathType Container) { @(Get-ChildItem -LiteralPath $Nodes -Filter '*.txt' -File | Sort-Object Name) } else { @(Get-Item -LiteralPath $Nodes) }
    if (-not @($files).Count) { throw 'No node files found. Run scripts/Get-Pre-Inventory.ps1 or pass -Nodes.' }
    foreach ($file in $files) {
        $sourceHashes.Add([ordered]@{name=$file.Name;sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()})
        Write-Host ('Inspecting: '+$file.Name)
        $inspect = Join-Path $scratch ([guid]::NewGuid().ToString('N') + '.ndjson')
        $errorFile = $inspect + '.err'
        $inspectionChild = Start-BatchChild $Core ('--inspect-list "' + $file.FullName + '"') $inspect $errorFile $owned
        $inspectionResult = Wait-BatchChild $inspectionChild 120000
        $inspectionExitCode = $inspectionResult.ExitCode
        if ($inspectionResult.Reason -or $null -eq $inspectionExitCode -or $inspectionExitCode -ne 0) {
            $failureReason = if ($inspectionResult.Reason) { $inspectionResult.Reason } elseif ($null -eq $inspectionExitCode) { 'EXIT_CODE_UNAVAILABLE' } else { 'NONZERO_EXIT' }
            $exitHex = if ($null -eq $inspectionExitCode) { $null } else { '0x' + ([int64]$inspectionExitCode -band 4294967295).ToString('X8') }
            $stderr = if (Test-Path -LiteralPath $errorFile) { Read-BatchOutput $errorFile } else { '' }
            # This core never prints credentials to stderr. Also redact URI/UUID forms.
            $stderr = [regex]::Replace($stderr,'(?i)\b(?:vless|vmess|trojan|ss)://\S+','[REDACTED_URI]')
            $stderr = [regex]::Replace($stderr,'(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b','[REDACTED_ID]')
            if ($stderr.Length -gt 8192) { $stderr = $stderr.Substring(0,8192) }
            $inventoryError = [ordered]@{source=$file.Name;reason=$failureReason;exit_code=$inspectionExitCode;exit_code_hex=$exitHex;stderr=$stderr;stdout_bytes=(Get-Item -LiteralPath $inspect).Length;process_mode='direct-dotnet';process_exited=$inspectionChild.Process.HasExited;output_complete=$inspectionResult.OutputComplete}
            [IO.File]::WriteAllText((Join-Path $OutputDirectory 'inventory-diagnostic.json'),($inventoryError | ConvertTo-Json -Depth 8),$encoding)
            $exitLabel = if ($null -eq $inspectionExitCode) { 'unavailable' } else { [string]$inspectionExitCode + ' (' + $exitHex + ')' }
            throw ('Inventory inspection failed: '+$file.Name+'; reason='+$failureReason+'; exit='+$exitLabel+'. See inventory-diagnostic.json in the report directory.')
        }
        Stop-BatchChild $inspectionChild $owned
        $inspectionChild = $null
        $uris = [IO.File]::ReadAllLines($file.FullName)
        foreach ($line in [IO.File]::ReadLines($inspect)) {
            $row = $line | ConvertFrom-Json
            foreach ($field in @('alpn_compatibility','alpn_configuration_reason_code','protocol','transport','security','cipher','flow','fingerprint','mode','header_type','finalmask','feature_family','plugin','plugin_mux','websocket_early_data','vmess_authentication','alter_id')) {
                if (-not $row.PSObject.Properties[$field]) { $row | Add-Member NoteProperty $field '' }
            }
            if (-not $row.PSObject.Properties['missing_features']) { $row | Add-Member NoteProperty missing_features @() }
            $row | Add-Member NoteProperty source $file.Name
            $catalog.Add([pscustomobject]@{Row=$row;Uri=$uris[$row.line-1].Trim();Key=($file.Name+':'+$row.line)})
        }
    }
    # Round-robin across actual feature groups; Limit does not take the first N links.
    $candidates = @($catalog | Where-Object { $_.Row.parsed -and $_.Row.connectable_by_this_build })
    $groups = @($candidates | Group-Object { $_.Row.feature_family+'|'+$_.Row.protocol+'|'+$_.Row.transport+'|'+$_.Row.security+'|'+$_.Row.cipher+'|'+$_.Row.flow+'|'+$_.Row.fingerprint+'|'+$_.Row.mode+'|'+$_.Row.header_type+'|'+$_.Row.finalmask } | Sort-Object Name)
    $queue = New-Object Collections.Generic.List[object]
    for ($offset=0; ; $offset++) {
        $added = $false
        foreach ($group in $groups) { if ($offset -lt $group.Count) { $queue.Add($group.Group[$offset]); $added=$true } }
        if (-not $added) { break }
    }
    if ($Limit -gt 0 -and $queue.Count -gt $Limit) { $queue = @($queue | Select-Object -First $Limit) }
    $selectedCount=$queue.Count
    foreach ($item in $queue) { $scheduled.Add($item.Key) | Out-Null }
    foreach ($item in $catalog) {
        $row = $item.Row
        if (-not $row.parsed) { $row | Add-Member NoteProperty status 'PARSE_INVALID'; Save-Row $row }
        elseif (-not $row.connectable_by_this_build) { $row | Add-Member NoteProperty status 'UNSUPPORTED'; Save-Row $row }
        elseif ($InspectOnly -or -not $scheduled.Contains($item.Key)) { $row | Add-Member NoteProperty status 'NOT_TESTED'; Save-Row $row }
    }
    Write-Host ('Inventory: '+$catalog.Count+'; supported configurations: '+$candidates.Count+'; selected: '+$queue.Count+'; concurrency: '+$Concurrency)
    if (-not $InspectOnly) {
        $pool = [RunspaceFactory]::CreateRunspacePool(1,$Concurrency); $pool.Open()
        $index = 0
        while ($index -lt $queue.Count -or $jobs.Count -gt 0) {
            while ($index -lt $queue.Count -and $jobs.Count -lt $Concurrency) {
                $ps = [PowerShell]::Create(); $ps.RunspacePool = $pool
                $ps.AddScript($worker.ToString()).AddArgument($queue[$index]).AddArgument($Core).AddArgument($Curl).AddArgument($Url).AddArgument($TimeoutSeconds).AddArgument($ExpectedBodySha256).AddArgument($scratch).AddArgument($owned).AddArgument($TestCaFile).AddArgument($processHelper) | Out-Null
                $jobs.Add([pscustomobject]@{Shell=$ps;Handle=$ps.BeginInvoke();Item=$queue[$index]}); $index++
            }
            for ($j=$jobs.Count-1; $j -ge 0; $j--) {
                $job = $jobs[$j]
                if ($job.Handle.IsCompleted) {
                    $values = @($job.Shell.EndInvoke($job.Handle))
                    if ($values.Count -ne 1) { throw 'Batch worker did not return exactly one result.' }
                    Save-Row $values[0]
                    Write-Host ($values[0].node_id+' '+$values[0].status+' '+$values[0].phase)
                    $job.Shell.Dispose(); $jobs.RemoveAt($j)
                }
            }
            if ($jobs.Count) { Start-Sleep -Milliseconds 50 }
        }
    }
    $completed = $true
} finally {
    # Release blocking curl waits before stopping runspaces.
    foreach ($entry in $owned.ToArray()) { try { if (-not $entry.Value.HasExited) { $entry.Value.Kill() } } catch {} }
    Stop-BatchChild $inspectionChild $owned
    foreach ($job in $jobs) { try { $job.Shell.Stop(); $job.Shell.Dispose() } catch {} }
    foreach ($entry in $owned.ToArray()) { try { if (-not $entry.Value.HasExited) { $entry.Value.Kill() }; $entry.Value.Dispose() } catch {} }
    if ($pool) { $pool.Close(); $pool.Dispose() }
    $known = New-Object Collections.Generic.HashSet[string]
    foreach ($r in $results) { $known.Add($r.source+':'+$r.line) | Out-Null }
    foreach ($item in $catalog) {
        if (-not $known.Contains($item.Key)) { $r=$item.Row; $r | Add-Member NoteProperty status 'CANCELLED'; Save-Row $r }
    }
    $writer.Dispose()
    $results | Select-Object source,line,node_id,protocol,transport,security,cipher,flow,fingerprint,mode,header_type,finalmask,alpn_compatibility,alpn_configuration_reason_code,status,failure_scope,phase,reason_code,uri_parsed,config_valid,runner_reason_code,readiness_reason,core_exit_code,core_output_complete,core_stopped_by_runner,curl_wait_reason,curl_output_complete,curl_error_class,core_failure_count,@{n='first_core_reason';e={Get-ReportCause $_ 'first_core_failure' 'reason_code'}},@{n='first_core_phase';e={Get-ReportCause $_ 'first_core_failure' 'phase'}},@{n='first_core_connection_id';e={Get-ReportCause $_ 'first_core_failure' 'connection_id'}},@{n='first_core_timestamp_ms';e={Get-ReportCause $_ 'first_core_failure' 'timestamp_unix_ms'}},@{n='last_core_reason';e={Get-ReportCause $_ 'last_core_failure' 'reason_code'}},@{n='last_core_phase';e={Get-ReportCause $_ 'last_core_failure' 'phase'}},@{n='last_core_connection_id';e={Get-ReportCause $_ 'last_core_failure' 'connection_id'}},@{n='last_core_timestamp_ms';e={Get-ReportCause $_ 'last_core_failure' 'timestamp_unix_ms'}},native_status,native_status_hex,transport_http_status,transport_http_header_name,negotiated_alpn,tls_version,curl_exit_code,http_code,bytes,seconds,body_sha256,@{n='missing_features';e={$_.missing_features -join ';'}} | Export-Csv -LiteralPath (Join-Path $OutputDirectory 'results.csv') -NoTypeInformation -Encoding UTF8
    $summary = [ordered]@{schema='vpn-batch-v4';script_revision='0.4.2';process_mode='direct-dotnet';completed=$completed;inventory_error=$inventoryError;core_sha256=(Get-FileHash -LiteralPath $Core -Algorithm SHA256).Hash.ToLowerInvariant();powershell_version=$PSVersionTable.PSVersion.ToString();platform=[Environment]::OSVersion.VersionString;source_files=@($sourceHashes.ToArray());generated_utc=[DateTime]::UtcNow.ToString('o');inventory=$catalog.Count;selected=$selectedCount;finished=@($results | Where-Object { $_.status -in @('PASS','FAIL') }).Count;timeout_seconds=$TimeoutSeconds;connect_timeout_ms=([Math]::Min(120000,$TimeoutSeconds*1000));idle_timeout_ms=([Math]::Min(600000,$TimeoutSeconds*1000));readiness_timeout_ms=10000;curl_wait_timeout_ms=(($TimeoutSeconds+5)*1000);inventory_wait_timeout_ms=120000;inspect_only=[bool]$InspectOnly;concurrency=$Concurrency;url=$Url;statuses=@($results | Group-Object status | ForEach-Object {[ordered]@{status=$_.Name;count=$_.Count}});groups=@($results | Group-Object { $_.feature_family+'|'+$_.protocol+'|'+$_.transport+'|'+$_.security+'|'+$_.cipher+'|'+$_.fingerprint+'|'+$_.mode+'|'+$_.finalmask } | ForEach-Object {[ordered]@{group=$_.Name;statuses=@($_.Group | Group-Object status | ForEach-Object {[ordered]@{status=$_.Name;count=$_.Count}})}})}
    [IO.File]::WriteAllText((Join-Path $OutputDirectory 'summary.json'),($summary | ConvertTo-Json -Depth 12),$encoding)
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host ('Reports: '+$OutputDirectory)
}
