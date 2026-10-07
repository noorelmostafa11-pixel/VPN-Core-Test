"""Exercise the real PowerShell report code using deterministic owned children."""
import json,os,pathlib,subprocess,tempfile,unittest
from test_core import ROOT,BIN
from test_batch import PW
from test_repairs_042 import URI

@unittest.skipUnless(PW and os.name=='posix','Requires PowerShell plus POSIX child harness')
class RepairBatchTests(unittest.TestCase):
    def run_case(self,curl_exit,expected_reason,expected_scope,tunnel_ready=None):
        with tempfile.TemporaryDirectory() as td:
            td=pathlib.Path(td);nodes=td/'nodes.txt';nodes.write_text(URI+'\n')
            core=td/'core';curl=td/'curl';report=td/'report'
            core.write_text('''#!/usr/bin/python3
import sys,os,json,time,pathlib
if '--inspect-list' in sys.argv:os.execv('''+repr(str(BIN))+''',[str('''+repr(str(BIN))+''')]+sys.argv[1:])
cfg=dict(line.split('=',1) for line in pathlib.Path(sys.argv[2]).read_text().splitlines())
pathlib.Path(cfg['ready_file']).write_text(json.dumps({'pid':os.getpid(),'port':12345}))
def fail(reason,phase,connection):
 print('[connection '+str(connection)+'] diagnostic='+json.dumps({'event':'failure','connection_id':connection,'timestamp_unix_ms':int(time.time()*1000),'phase':phase,'reason_code':reason,'native_status':311,'http_status':0,'tls_version':'','alpn':'','tunnel_ready':'''+repr(tunnel_ready)+'''}),flush=True)
fail('TLS_CERTIFICATE_NAME','TLS_FAILED',1)
time.sleep(.1)
fail('XHTTP_CLIENT_WAIT','RELAY_FAILED',2)
time.sleep(30)
''')
            curl.write_text(f'#!/usr/bin/python3\nimport sys,time\ntime.sleep(.4)\nprint("000|0|0.4")\nprint("private-password-or-URL",file=sys.stderr)\nsys.exit({curl_exit})\n')
            core.chmod(0o700);curl.chmod(0o700)
            run=subprocess.run([PW,'-NoProfile','-File',str(ROOT/'scripts/Test-Batch.ps1'),'-Core',str(core),'-Curl',str(curl),'-Nodes',str(nodes),'-TimeoutSeconds','5','-OutputDirectory',str(report)],text=True,capture_output=True,timeout=30)
            self.assertEqual(run.returncode,0,run.stdout+run.stderr)
            row=json.loads((report/'results.ndjson').read_text())
            self.assertEqual(row['reason_code'],expected_reason);self.assertEqual(row['failure_scope'],expected_scope);self.assertEqual(row['first_core_failure']['connection_id'],1);self.assertEqual(row['last_core_failure']['reason_code'],'XHTTP_CLIENT_WAIT');self.assertEqual(row['core_failure_count'],2);self.assertEqual(row['curl_exit_code'],curl_exit);self.assertTrue(row['curl_output_complete']);self.assertTrue(row['core_stopped_by_runner'])
            summary=json.loads((report/'summary.json').read_text());self.assertEqual(summary['timeout_seconds'],5);self.assertEqual(summary['selected'],1);self.assertEqual(summary['finished'],1)
            for file in report.iterdir():
                text=file.read_text(encoding='utf-8-sig');self.assertNotIn('private-password-or-URL',text);self.assertNotIn(URI,text)

    def test_first_failure_and_process_context_survive_second_failure(self):
        self.run_case(97,'TLS_CERTIFICATE_NAME','OUTER_TUNNEL')
    def test_destination_tls_does_not_become_outer_cleanup_failure(self):
        self.run_case(60,'HTTPS_CERTIFICATE','HTTPS_DESTINATION_TLS')
