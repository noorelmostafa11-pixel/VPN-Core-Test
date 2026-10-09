"""Preserve independent request, tunnel and cleanup evidence in real reports."""
import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
RUNNER=ROOT/'scripts/Test-Nodes.py'
spec=importlib.util.spec_from_file_location('node_diagnostics',RUNNER)
runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)

def event(reason,phase='TLS_FAILED',ready=False,connection=1,stamp=30,http=0):
    return {'event':'failure','connection_id':connection,'timestamp_unix_ms':stamp,
            'phase':phase,'reason_code':reason,'tunnel_ready':ready,'native_status':311,
            'http_status':http,'extra_secret':'PRIVATE-ERROR-CONTENT'}

def negotiated():
    return {'event':'negotiated','connection_id':1,'timestamp_unix_ms':10,'tls_version':'TLS1.3','alpn':'http/1.1'}

@unittest.skipUnless(os.name=='posix','Deterministic executable fixtures require POSIX')
class NodeDiagnosticsTests(unittest.TestCase):
    def run_case(self,events,code=35,http=0,stderr='wrong version number PRIVATE-CURL-SECRET',wait=False,startup=False):
        with tempfile.TemporaryDirectory() as td:
            td=pathlib.Path(td);nodes=td/'nodes';nodes.mkdir()
            uri='trojan://PRIVATE-NODE-CREDENTIAL@127.0.0.1:9?security=tls#keep-original'
            source=nodes/'trojan.txt';source.write_text(uri+'\n')
            manifest=td/'manifest.json'
            manifest.write_text(json.dumps({'commit':'synthetic-pre','files':[{'name':source.name,'sha256':hashlib.sha256(source.read_bytes()).hexdigest()}]}))
            core=td/'core';curl=td/'curl';marker=td/'events-ready';output=td/'reports'
            cleanup=[event('TLS_PROVIDER_ENCRYPT',phase='CANCELLED',ready=True,stamp=40),
                     event('HTTP_UPGRADE_STATUS',phase='TRANSPORT_FAILED',ready=True,stamp=41,http=403)]
            core.write_text('#!'+sys.executable+'\n'+'''
import hashlib,json,os,pathlib,signal,sys,time
if '--inspect-list' in sys.argv:
 for line in pathlib.Path(sys.argv[-1]).read_text().splitlines():
  print(json.dumps({'parsed':True,'uri_parsed':True,'node_id':hashlib.sha256(line.strip().encode()).hexdigest()[:20]}))
 sys.exit(0)
cfg=dict(line.split('=',1) for line in pathlib.Path(sys.argv[-1]).read_text().splitlines())
def publish(value):
 print('[connection '+str(value['connection_id'])+'] diagnostic='+json.dumps(value),flush=True)
def stop(*_):
 for value in '''+repr(cleanup)+''':publish(value)
 sys.exit(0)
signal.signal(signal.SIGTERM,stop)
if not '''+repr(startup)+''':pathlib.Path(cfg['ready_file']).write_text(json.dumps({'pid':os.getpid(),'port':12345}))
for value in '''+repr(events)+''':publish(value)
pathlib.Path('''+repr(str(marker))+''').write_text('ready')
if '''+repr(startup)+''':sys.exit(22)
while True:time.sleep(.1)
''')
            curl.write_text('#!'+sys.executable+'\n'+'''
import pathlib,sys,time
marker=pathlib.Path('''+repr(str(marker))+''')
until=time.monotonic()+2
while not marker.exists() and time.monotonic()<until:time.sleep(.005)
if '''+repr(wait)+''':time.sleep(10)
print('''+repr(f'{http:03d}|0|0.2|0.01|0.1|0.15|1|0')+''')
print('''+repr(stderr)+''',file=sys.stderr)
sys.exit('''+repr(code)+''')
''')
            core.chmod(0o700);curl.chmod(0o700)
            original_hash=hashlib.sha256(source.read_bytes()).hexdigest()
            result=subprocess.run([sys.executable,str(RUNNER),'--core',str(core),'--curl',str(curl),
                '--nodes',str(nodes),'--pre-manifest',str(manifest),'--source-commit','fixture',
                '--output',str(output),'--shards','1','--concurrency','1','--timeout','1'],
                capture_output=True,text=True,timeout=12)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),original_hash)
            row=json.loads((output/'results.ndjson').read_text())
            self.assertEqual(row['node_id'],hashlib.sha256(uri.encode()).hexdigest()[:20])
            for file in output.iterdir():
                text=file.read_text()
                for private in (uri,'PRIVATE-NODE-CREDENTIAL','PRIVATE-CURL-SECRET','PRIVATE-ERROR-CONTENT'):
                    self.assertNotIn(private,text)
            return row,json.loads((output/'summary.json').read_text())

    def test_first_outer_failure_survives_later_failure_and_cleanup(self):
        row,summary=self.run_case([event('TLS_CERTIFICATE_NAME'),event('XHTTP_CLIENT_WAIT',phase='RELAY_FAILED',connection=2,stamp=20)],code=97)
        self.assertEqual(row['reason_code'],'TLS_CERTIFICATE_NAME')
        self.assertEqual(row['curl_exit_code'],97)
        self.assertEqual(row['curl_reason_code'],'CURL_97')
        self.assertEqual(row['first_core_failure']['connection_id'],1)
        self.assertEqual(row['first_core_failure']['reason_code'],'TLS_CERTIFICATE_NAME')
        self.assertEqual(row['first_cleanup_core_failure']['reason_code'],'TLS_PROVIDER_ENCRYPT')
        self.assertFalse(row['first_cleanup_core_failure']['observed_before_cleanup'])
        self.assertEqual(row['core_pre_cleanup_failure_count'],2)
        self.assertEqual(row['core_cleanup_failure_count'],2)
        self.assertEqual(row['core_failure_count'],4)
        self.assertFalse(row['core_tunnel_ready'])
        self.assertEqual(summary['curl_reasons'],{'CURL_97':1})

    def test_curl_tls_error_does_not_become_a_relay_or_cleanup_error(self):
        row,_=self.run_case([negotiated(),event('SOCKET_RECEIVE',phase='RELAY_FAILED',ready=True)])
        self.assertEqual(row['reason_code'],'CURL_35')
        self.assertEqual(row['curl_exit_code'],35)
        self.assertEqual(row['curl_tls_error_class'],'TLS_RECORD_VERSION')
        self.assertTrue(row['core_tunnel_ready'])
        self.assertEqual(row['first_core_failure']['reason_code'],'SOCKET_RECEIVE')
        self.assertEqual(row['first_failure']['source'],'CURL')
        self.assertEqual(row['failure_scope'],'HTTPS_TLS_OR_TUNNEL')

    def test_cleanup_only_is_not_an_earlier_core_cause(self):
        row,_=self.run_case([negotiated()])
        self.assertEqual(row['reason_code'],'CURL_35')
        self.assertIsNone(row['first_core_failure'])
        self.assertEqual(row['core_pre_cleanup_failure_count'],0)
        self.assertEqual(row['core_cleanup_failure_count'],2)
        self.assertTrue(row['core_stopped_by_runner'])
        self.assertEqual(row['core_exit_code'],0)

    def test_all_2xx_statuses_keep_original_success_rule(self):
        for status in (200,202,204,206,299):
            with self.subTest(status=status):
                row,_=self.run_case([negotiated()],code=0,http=status)
                self.assertEqual(row['status'],'PASS')
                self.assertEqual(row['reason_code'],'HTTP_2XX')
                self.assertEqual(row['curl_exit_code'],0)
                self.assertEqual(row['http_status'],status)
                self.assertEqual(row['curl_http_status'],status)
                self.assertEqual(row['failure_scope'],'NONE')
                self.assertEqual(row['core_cleanup_failure_count'],2)

    def test_http_error_is_not_replaced_by_outer_http_status(self):
        row,_=self.run_case([negotiated()],code=0,http=404)
        self.assertEqual(row['status'],'FAIL')
        self.assertEqual(row['reason_code'],'HTTP_STATUS')
        self.assertEqual(row['http_status'],404)
        self.assertEqual(row['curl_http_status'],404)
        self.assertEqual(row['first_cleanup_core_failure']['reason_code'],'TLS_PROVIDER_ENCRYPT')
        self.assertEqual(row['last_core_failure']['http_status'],403)

    def test_curl_timeout_and_unknown_tunnel_readiness_remain_distinct(self):
        row,_=self.run_case([],code=28,stderr='Operation timed out PRIVATE-CURL-SECRET')
        self.assertEqual(row['curl_exit_code'],28)
        self.assertEqual(row['reason_code'],'CURL_28')
        self.assertIsNone(row['core_tunnel_ready'])
        self.assertIsNone(row['first_core_failure'])

    def test_wait_timeout_does_not_invent_a_curl_exit_code(self):
        row,_=self.run_case([negotiated()],wait=True)
        self.assertEqual(row['status'],'FAIL')
        self.assertIsNone(row['curl_exit_code'])
        self.assertFalse(row['curl_output_complete'])
        self.assertEqual(row['curl_wait_reason'],'SUBPROCESS_TIMEOUT')
        self.assertEqual(row['curl_reason_code'],'CURL_EXIT_UNAVAILABLE')
        self.assertEqual(row['first_failure']['source'],'CURL_PROCESS')

    def test_startup_exit_keeps_core_diagnostic_without_running_curl(self):
        row,_=self.run_case([event('TLS_PROVIDER_CREATE')],startup=True)
        self.assertEqual(row['reason_code'],'CORE_EXITED_BEFORE_READY')
        self.assertFalse(row['network_test_performed'])
        self.assertEqual(row['core_exit_code'],22)
        self.assertFalse(row['core_stopped_by_runner'])
        self.assertEqual(row['first_core_failure']['reason_code'],'TLS_PROVIDER_CREATE')


class DiagnosticSanitizationTests(unittest.TestCase):
    def test_optional_metrics_and_metadata_cannot_change_success_or_export_names(self):
        metrics=runner.curl_metrics('204|0|0.2|unsupported|nan|0.15|unsupported|0')
        self.assertEqual(metrics['curl_http_status'],204)
        self.assertNotIn('curl_connect_ms',metrics)
        self.assertEqual(metrics['curl_starttransfer_ms'],150)
        metadata=runner.inspection_metadata({'protocol':'vless','transport':'raw','security':'reality',
            'flow':'xtls-rprx-vision','fingerprint':'PRIVATE-FINGERPRINT','alpn':['h2','PRIVATE-ALPN'],
            'websocket_early_data':True,'extra':'PRIVATE'})
        self.assertEqual(metadata['fingerprint'],'OTHER')
        self.assertEqual(metadata['alpn'],['h2','OTHER'])
        self.assertIsNone(metadata['websocket_early_data'])
        self.assertNotIn('extra',metadata)

    def test_only_valid_fields_leave_core_diagnostics(self):
        value=event('TLS_ALERT');value.update(alpn='PRIVATE-ALPN',tls_version='PRIVATE-VERSION')
        line='[connection 1] diagnostic='+json.dumps(value)
        safe=runner.diagnostic(line)
        self.assertEqual(safe['alpn'],'OTHER')
        self.assertEqual(safe['tls_version'],'')
        self.assertNotIn('extra_secret',safe)
        for mutation in ({'reason_code':'trojan://PRIVATE'}, {'phase':{}}, {'native_status':True},
                         {'connection_id':2}, {'http_status':99}, {'native_status':2**32}):
            bad=dict(value,**mutation)
            self.assertIsNone(runner.diagnostic('[connection 1] diagnostic='+json.dumps(bad)))

    def test_partial_and_oversized_lines_cannot_create_false_causes(self):
        with tempfile.TemporaryDirectory() as td:
            path=pathlib.Path(td)/'log'
            valid='[connection 1] diagnostic='+json.dumps(event('TLS_ALERT'))+'\n'
            path.write_text('x'*9000+valid+valid+valid.rstrip('\n'))
            events=runner.read_diagnostics(path,path.stat().st_size)
            self.assertEqual(len(events),1)
            self.assertEqual(events[0]['reason_code'],'TLS_ALERT')

    def test_tls_subclasses_never_export_raw_stderr(self):
        for phrase,kind in [('unexpected eof','TLS_UNEXPECTED_EOF'),('handshake failure','TLS_HANDSHAKE_FAILURE'),
                            ('no application protocol','TLS_ALPN'),('ssl_error_syscall','TLS_IO')]:
            self.assertEqual(runner.tls_error_class(35,phrase+' PRIVATE'),kind)
        self.assertEqual(runner.tls_error_class(28,'PRIVATE'),'NOT_APPLICABLE')


if __name__=='__main__':unittest.main()
