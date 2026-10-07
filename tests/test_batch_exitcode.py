"""Actual .NET process regressions, including large pipes and fast exits.

Results establish behavior only on the runtime/platform used for execution.
"""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest
from test_core import ROOT, BIN

PW = os.environ.get('VPN_CORE_POWERSHELL')
CURL = shutil.which('curl') or 'curl.exe'
POISON_WRAPPER = r'''
param([string]$Batch,[string]$Nodes,[string]$Core,[string]$Curl,[string]$OutputDirectory)
function Start-Process { throw 'The batch must not call Start-Process.' }
& $Batch -Nodes $Nodes -Core $Core -Curl $Curl -OutputDirectory $OutputDirectory -InspectOnly
'''
CHILD = r'''
param([string]$Mode)
if ($Mode -eq 'nonzero') { exit 23 }
if ($Mode -eq 'timeout') { [Threading.Thread]::Sleep(30000); exit 0 }
if ($Mode -eq 'delayed-write') { [Threading.Thread]::Sleep(4200); [Console]::Write('late'); exit 0 }
if ($Mode -eq 'slow-drain') {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = if (Test-Path (Join-Path $PSHOME 'pwsh.exe')) { Join-Path $PSHOME 'pwsh.exe' } elseif (Test-Path (Join-Path $PSHOME 'powershell.exe')) { Join-Path $PSHOME 'powershell.exe' } else { Join-Path $PSHOME 'pwsh' }
    $info.Arguments = '-NoProfile -File "' + $PSCommandPath + '" -Mode delayed-write'
    $info.UseShellExecute = $false
    $descendant = New-Object Diagnostics.Process
    $descendant.StartInfo = $info
    [void]$descendant.Start()
    $descendant.Dispose()
    exit 0
}
if ($Mode -eq 'flood') {
    $stdout = [Console]::OpenStandardOutput()
    $stderr = [Console]::OpenStandardError()
    $out = [Text.Encoding]::UTF8.GetBytes(('عقدة ✓ output line' + "`n") * 4096)
    $err = [Text.Encoding]::UTF8.GetBytes(('synthetic stderr line' + "`n") * 4096)
    for ($i=0; $i -lt 48; $i++) {
        $stdout.Write($out,0,$out.Length)
        $stderr.Write($err,0,$err.Length)
    }
    $stdout.Flush(); $stderr.Flush()
}
exit 0
'''
HELPER_HARNESS = r'''
param([string]$Helper,[string]$Executable,[string]$ChildScript,[string]$Temp,[string]$Mode)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
. $Helper
function Start-Process { throw 'The helper must not call Start-Process.' }
$owned = New-Object 'Collections.Concurrent.ConcurrentDictionary[int,System.Diagnostics.Process]'
$child = $null
try {
    $stdout = Join-Path $Temp 'stdout.bin'; $stderr = Join-Path $Temp 'stderr.bin'
    $arguments = '-NoProfile -File "' + $ChildScript + '" -Mode ' + $Mode
    if ($Mode -eq 'startup-failure') {
        $failed = $false
        try { $child = Start-BatchChild ($Executable + '.missing') $arguments $stdout $stderr $owned }
        catch { $failed = $true }
        if (-not $failed -or $owned.Count -ne 0) { throw 'Startup failure leaked a child.' }
        Remove-Item -LiteralPath $stdout,$stderr -Force
        @{startup_failed=$failed;owned=$owned.Count} | ConvertTo-Json -Compress
        return
    }
    $child = Start-BatchChild $Executable $arguments $stdout $stderr $owned
    if ($Mode -eq 'masked-getter') {
        $child.Process | Add-Member ScriptProperty ExitCode { $null } -Force
    }
    $timeout = if ($Mode -eq 'timeout') { 200 } else { 15000 }
    $result = Wait-BatchChild $child $timeout
    $exited = $child.Process.HasExited
    $captured = if ($Mode -eq 'flood') { (Read-BatchOutput $stdout).Length } else { 0 }
    Stop-BatchChild $child $owned
    @{exit_code=$result.ExitCode;reason=$result.Reason;finished=$result.Finished;output_complete=$result.OutputComplete;exited=$exited;owned=$owned.Count;captured_chars=$captured;drain_ms=$result.DrainMilliseconds;stdout_bytes=$result.StdoutBytes;stderr_bytes=$result.StderrBytes;stdout_state=$result.StdoutState;stderr_state=$result.StderrState} | ConvertTo-Json -Compress
} finally { Stop-BatchChild $child $owned }
'''

@unittest.skipUnless(PW, 'Set VPN_CORE_POWERSHELL')
class BatchExitCodeTests(unittest.TestCase):
    def invoke_inventory(self, temp, *, core=None, poison=True):
        temp = pathlib.Path(temp)
        nodes = temp / 'nodes.txt'
        nodes.write_text('vless://12345678-1234-4567-9234-567812345678@127.0.0.1:443?security=none&type=raw\n')
        output = temp / 'report'
        if poison:
            harness = temp / 'poison-start-process.ps1'
            harness.write_text(POISON_WRAPPER)
            argv = [PW, '-NoProfile', '-File', str(harness), '-Batch', str(ROOT/'scripts/Test-Batch.ps1')]
        else:
            argv = [PW, '-NoProfile', '-File', str(ROOT/'scripts/Test-Batch.ps1'), '-InspectOnly']
        argv += ['-Nodes', str(nodes), '-Core', str(core or BIN), '-Curl', CURL, '-OutputDirectory', str(output)]
        result = subprocess.run(argv, text=True, capture_output=True, timeout=20)
        return result, output

    def invoke_helper(self, temp, mode):
        temp = pathlib.Path(temp)
        harness = temp / 'helper-harness.ps1'
        harness.write_text(HELPER_HARNESS, encoding='utf-8-sig')
        child = temp / 'عملية سريعة child.ps1'
        child.write_text(CHILD, encoding='utf-8-sig')
        result = subprocess.run([PW, '-NoProfile', '-File', str(harness), '-Helper', str(ROOT/'scripts/Batch-Process.ps1'), '-Executable', PW, '-ChildScript', str(child), '-Temp', str(temp), '-Mode', mode], text=True, capture_output=True, timeout=25)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout.strip())

    def test_inventory_works_without_start_process(self):
        with tempfile.TemporaryDirectory() as temp:
            result, output = self.invoke_inventory(temp)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            summary = json.loads((output/'summary.json').read_text())
            self.assertTrue(summary['completed'])
            self.assertEqual(summary['inventory'], 1)
            self.assertIsNone(summary['inventory_error'])
            self.assertEqual(summary['script_revision'], (ROOT/'VERSION').read_text().strip())
            self.assertEqual(summary['process_mode'], 'direct-dotnet')
    def test_structured_diagnostics_whitelist(self):
        with tempfile.TemporaryDirectory() as temp:
            temp=pathlib.Path(temp);log=temp/'core.log';script=temp/'read.ps1'
            valid={'event':'failure','phase':'TRANSPORT_FAILED','reason_code':'HTTP_UPGRADE_STATUS','native_status':4294967295,'native_status_hex':'SECRET-INJECTION','http_status':403,'tls_version':'TLS1.3','alpn':'http/1.1','extra_secret':'DO-NOT-EXPORT'}
            invalid=dict(valid,reason_code='trojan://DO-NOT-EXPORT')
            negotiated={'event':'negotiated','tls_version':'TLSv1.3','alpn':'h2','secret':'DO-NOT-EXPORT'}
            log.write_text('\n'.join('[connection 1] diagnostic='+json.dumps(v) for v in [valid,invalid,negotiated])+'\n[connection 2] diagnostic={malformed}\n')
            script.write_text('param([string]$Helper,[string]$Log)\nSet-StrictMode -Version 2\n. $Helper\nConvertTo-Json -Depth 5 -InputObject @(Read-BatchDiagnostic $Log)\n')
            r=subprocess.run([PW,'-NoProfile','-File',str(script),'-Helper',str(ROOT/'scripts/Batch-Process.ps1'),'-Log',str(log)],text=True,capture_output=True,timeout=20)
            self.assertEqual(r.returncode,0,r.stdout+r.stderr);rows=json.loads(r.stdout);self.assertEqual(len(rows),2)
            self.assertEqual(rows[0]['native_status_hex'],'0xFFFFFFFF');self.assertEqual(rows[0]['http_status'],403);self.assertEqual(rows[1]['alpn'],'h2')
            self.assertNotIn('DO-NOT-EXPORT',r.stdout);self.assertNotIn('SECRET-INJECTION',r.stdout)

    def test_zero_exit_and_unicode_space_path(self):
        with tempfile.TemporaryDirectory(prefix='اختبار دفعات ') as temp:
            result = self.invoke_helper(temp, 'zero')
            self.assertEqual(result['exit_code'], 0)
            self.assertEqual(result['reason'], '')
            self.assertTrue(result['output_complete'])
            self.assertEqual(result['owned'], 0)

    def test_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as temp:
            result = self.invoke_helper(temp, 'nonzero')
            self.assertEqual(result['exit_code'], 23)
            self.assertEqual(result['reason'], '')
            self.assertTrue(result['finished'])

    def test_dotnet_getter_survives_masked_powershell_property(self):
        with tempfile.TemporaryDirectory() as temp:
            result = self.invoke_helper(temp, 'masked-getter')
            self.assertEqual(result['exit_code'], 0)
            self.assertEqual(result['reason'], '')

    def test_large_stdout_and_stderr_exact_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            result = self.invoke_helper(temp, 'flood')
            self.assertEqual(result['exit_code'], 0)
            self.assertTrue(result['output_complete'])
            self.assertEqual(result['captured_chars'], len('عقدة ✓ output line\n') * 4096 * 48)
            for name, chunk in [('stdout.bin', 'عقدة ✓ output line\n'.encode()), ('stderr.bin', b'synthetic stderr line\n')]:
                expected = chunk * (4096 * 48)
                actual = (pathlib.Path(temp)/name).read_bytes()
                self.assertEqual(len(actual), len(expected))
                self.assertEqual(hashlib.sha256(actual).digest(), hashlib.sha256(expected).digest())

    def test_sixteen_concurrent_children_capture_exact_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td)
            child = td/'flood.ps1'; child.write_text(CHILD, encoding='utf-8-sig')
            harness = td/'stress.ps1'
            harness.write_text(r'''param([string]$Helper,[string]$Executable,[string]$ChildScript,[string]$Temp)
$ErrorActionPreference='Stop'
. $Helper
$owned=New-Object 'Collections.Concurrent.ConcurrentDictionary[int,System.Diagnostics.Process]'
$children=@()
try {
    for ($i=0;$i -lt 16;$i++) {
        $children+=Start-BatchChild $Executable ('-NoProfile -File "'+$ChildScript+'" -Mode flood') (Join-Path $Temp ($i.ToString()+'.out')) (Join-Path $Temp ($i.ToString()+'.err')) $owned
    }
    foreach ($child in $children) {
        $r=Wait-BatchChild $child 30000
        if ($r.ExitCode -ne 0 -or $r.Reason -or -not $r.OutputComplete) { throw 'Concurrent output capture failed.' }
        Stop-BatchChild $child $owned
    }
    if ($owned.Count -ne 0) { throw 'Concurrent child leaked.' }
} finally { foreach ($child in $children) { Stop-BatchChild $child $owned } }
''', encoding='utf-8-sig')
            run=subprocess.run([PW,'-NoProfile','-File',str(harness),'-Helper',str(ROOT/'scripts/Batch-Process.ps1'),'-Executable',PW,'-ChildScript',str(child),'-Temp',str(td)],capture_output=True,text=True,timeout=120)
            self.assertEqual(run.returncode,0,run.stdout+run.stderr)
            for suffix,chunk in [('out','عقدة ✓ output line\n'.encode()),('err',b'synthetic stderr line\n')]:
                expected=chunk*(4096*48)
                for i in range(16):
                    data=(td/(str(i)+'.'+suffix)).read_bytes()
                    self.assertEqual(len(data),len(expected))
                    self.assertEqual(hashlib.sha256(data).digest(),hashlib.sha256(expected).digest())

    def test_delayed_inherited_pipe_is_fully_drained(self):
        with tempfile.TemporaryDirectory() as temp:
            result = self.invoke_helper(temp, 'slow-drain')
            self.assertEqual(result['exit_code'], 0)
            self.assertEqual(result['reason'], '')
            self.assertTrue(result['output_complete'])
            self.assertGreater(result['drain_ms'], 3000)
            self.assertEqual(result['stdout_bytes'], 4)
            self.assertEqual((pathlib.Path(temp)/'stdout.bin').read_bytes(), b'late')

    def test_timeout_kills_owned_child(self):
        with tempfile.TemporaryDirectory() as temp:
            result = self.invoke_helper(temp, 'timeout')
            self.assertEqual(result['reason'], 'TIMEOUT')
            self.assertFalse(result['finished'])
            self.assertTrue(result['exited'])
            self.assertEqual(result['owned'], 0)

    def test_startup_failure_closes_output_files(self):
        with tempfile.TemporaryDirectory() as temp:
            result = self.invoke_helper(temp, 'startup-failure')
            self.assertTrue(result['startup_failed'])
            self.assertEqual(result['owned'], 0)

    @unittest.skipUnless(os.name == 'posix', 'POSIX fast-exit fixture')
    def test_fast_native_exit_before_wait(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = pathlib.Path(temp)
            harness = temp/'fast-exit.ps1'
            harness.write_text(r'''
param([string]$Helper,[string]$Temp)
$ErrorActionPreference = 'Stop'
. $Helper
$owned = New-Object 'Collections.Concurrent.ConcurrentDictionary[int,System.Diagnostics.Process]'
for ($i=0; $i -lt 20; $i++) {
    $child = Start-BatchChild '/bin/sh' '-c "exit 23"' (Join-Path $Temp ($i.ToString()+'.out')) (Join-Path $Temp ($i.ToString()+'.err')) $owned
    try {
        Start-Sleep -Milliseconds 20
        $result = Wait-BatchChild $child 1000
        if ($result.ExitCode -ne 23 -or $result.Reason -or -not $result.OutputComplete) { throw 'Fast native exit was lost.' }
    } finally { Stop-BatchChild $child $owned }
}
if ($owned.Count -ne 0) { throw 'Owned child leaked.' }
''')
            result = subprocess.run([PW, '-NoProfile', '-File', str(harness), '-Helper', str(ROOT/'scripts/Batch-Process.ps1'), '-Temp', str(temp)], text=True, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(os.name == 'posix', 'POSIX test stub')
    def test_native_failure_retained_and_redacted(self):
        with tempfile.TemporaryDirectory() as temp:
            core = pathlib.Path(temp)/'failing-core'
            core.write_text("#!/bin/sh\nprintf '%s\\n' 'vpn-core: PARSE_INVALID: synthetic failure trojan://sensitive@127.0.0.1:443 12345678-1234-4567-9234-567812345678' >&2\nexit 23\n")
            core.chmod(0o700)
            result, output = self.invoke_inventory(temp, core=core, poison=False)
            self.assertNotEqual(result.returncode, 0)
            diagnostic = json.loads((output/'inventory-diagnostic.json').read_text())
            self.assertEqual(diagnostic['reason'], 'NONZERO_EXIT')
            self.assertEqual(diagnostic['exit_code'], 23)
            self.assertEqual(diagnostic['exit_code_hex'], '0x00000017')
            self.assertTrue(diagnostic['output_complete'])
            self.assertIn('synthetic failure', diagnostic['stderr'])
            for file in output.glob('*'):
                data = file.read_text(encoding='utf-8-sig')
                self.assertNotIn('sensitive', data)
                self.assertNotIn('12345678-1234-4567-9234-567812345678', data)

if __name__ == '__main__':
    unittest.main(verbosity=2)
