"""Bounded Windows readiness-file sharing retries, without weakening identity checks."""
import json,os,pathlib,subprocess,tempfile,unittest
from test_batch_exitcode import PW,ROOT

@unittest.skipUnless(PW and os.name=='nt','Windows file-sharing semantics')
class ReadyReadTests(unittest.TestCase):
    def test_reader_waits_for_a_temporary_exclusive_handle(self):
        with tempfile.TemporaryDirectory() as td:
            td=pathlib.Path(td);script=td/'ready.ps1'
            script.write_text(r'''param([string]$Helper,[string]$Temp,[string]$Mode)
$ErrorActionPreference='Stop'
if ($Mode -eq 'child') {
    $path=Join-Path $Temp 'ready.json'
    [IO.File]::WriteAllText($path,'{"pid":123,"port":234}')
    $handle=New-Object IO.FileStream($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
    try {
        [IO.File]::WriteAllText((Join-Path $Temp 'locked'),'1')
        Start-Sleep -Milliseconds 600
    } finally { $handle.Dispose() }
    return
}
. $Helper
$info=New-Object Diagnostics.ProcessStartInfo
$info.FileName=Join-Path $PSHOME 'powershell.exe'
if (-not (Test-Path $info.FileName)) { $info.FileName=Join-Path $PSHOME 'pwsh.exe' }
$info.UseShellExecute=$false
$info.Arguments='-NoProfile -File "'+$PSCommandPath+'" -Mode child -Temp "'+$Temp+'"'
$child=[Diagnostics.Process]::Start($info)
try {
    $end=[DateTime]::UtcNow.AddSeconds(10)
    while (-not (Test-Path (Join-Path $Temp 'locked'))) {
        if ($child.HasExited -or [DateTime]::UtcNow -gt $end) { throw 'fixture failed' }
        Start-Sleep -Milliseconds 10
    }
    $timer=[Diagnostics.Stopwatch]::StartNew()
    $state=Read-BatchReadyState (Join-Path $Temp 'ready.json') ([Diagnostics.Process]::GetCurrentProcess()) $timer 3000
    @{pid=$state.pid;port=$state.port;elapsed=$timer.ElapsedMilliseconds} | ConvertTo-Json -Compress
} finally {
    [void]$child.WaitForExit(3000)
    if (-not $child.HasExited) { $child.Kill() }
    $child.Dispose()
}
''',encoding='utf-8-sig')
            r=subprocess.run([PW,'-NoProfile','-File',str(script),'-Helper',str(ROOT/'scripts/Batch-Process.ps1'),'-Temp',str(td)],capture_output=True,text=True,timeout=20)
            self.assertEqual(r.returncode,0,r.stdout+r.stderr)
            result=json.loads(r.stdout);self.assertEqual(result['pid'],123);self.assertEqual(result['port'],234)
            self.assertGreater(result['elapsed'],100);self.assertLess(result['elapsed'],3000)

if __name__=='__main__':unittest.main(verbosity=2)
