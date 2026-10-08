"""Native thread teardown and handle ownership, separate from Python callbacks."""
import os,subprocess,unittest
from test_core import ROOT

class DnsWorkerTests(unittest.TestCase):
    def run_probe(self,mode):
        suffix='.exe' if os.name=='nt' else ''
        probe=os.environ.get('VPN_CORE_DNS_WORKER_PROBE',str(ROOT/'bin'/('dns-worker-probe'+suffix)))
        result=subprocess.run([probe,mode],capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('PASS:',result.stdout)
        print(result.stdout.strip(),flush=True)
    def test_success_joins_native_thread_cleanup(self):self.run_probe('cleanup')
    def test_timeout_and_stop_keep_native_context_alive(self):self.run_probe('drain')
    def test_native_callback_and_system_dns_do_not_retain_handles(self):self.run_probe('resources')
