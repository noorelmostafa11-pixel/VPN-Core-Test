"""Native thread teardown and handle ownership, separate from Python callbacks."""
import os,subprocess,unittest
from test_core import ROOT

class DnsWorkerTests(unittest.TestCase):
    def run_probe(self,mode,expected_returncode=0):
        suffix='.exe' if os.name=='nt' else ''
        probe=os.environ.get('VPN_CORE_DNS_WORKER_PROBE',str(ROOT/'bin'/('dns-worker-probe'+suffix)))
        result=subprocess.run([probe,mode],capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,expected_returncode,result.stdout+result.stderr)
        if expected_returncode==0:self.assertIn('PASS:',result.stdout)
        print(result.stdout.strip(),flush=True)
        return result
    def test_success_joins_native_thread_cleanup(self):self.run_probe('cleanup')
    def test_timeout_and_stop_keep_native_context_alive(self):self.run_probe('drain')
    def test_native_callback_and_system_dns_do_not_retain_handles(self):self.run_probe('resources')
    def test_resource_warmup_rejects_retained_handles(self):
        result=self.run_probe('resources-retained',expected_returncode=1)
        self.assertIn('DNS warmup handles did not stabilize',result.stderr)
