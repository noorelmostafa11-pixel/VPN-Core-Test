"""Runner cause attribution and fail-closed report diagnostics."""
import json,os,pathlib,subprocess,tempfile,unittest
from test_core import ROOT
from test_batch import PW
from test_repair_batch_042 import RepairBatchTests

@unittest.skipUnless(PW and os.name=='posix','POSIX deterministic child fixtures')
class RepositoryBatchRepairTests(unittest.TestCase):
    run_case=RepairBatchTests.run_case

    def test_https_handshake_does_not_hide_explicit_outer_failure(self):
        self.run_case(35,'TLS_CERTIFICATE_NAME','OUTER_TUNNEL',tunnel_ready=False)

    def test_https_handshake_cause_remains_unresolved_after_tunnel_ready(self):
        self.run_case(35,'HTTPS_TLS_HANDSHAKE','HTTPS_REQUEST_OR_TUNNEL',tunnel_ready=True)

    def test_unknown_tunnel_state_is_not_guessed(self):
        self.run_case(35,'HTTPS_TLS_HANDSHAKE','HTTPS_REQUEST_OR_TUNNEL')

    def test_report_records_runner_error_without_exporting_input(self):
        with tempfile.TemporaryDirectory() as td:
            td=pathlib.Path(td);core=td/'broken-inspector';nodes=td/'nodes.txt';report=td/'report'
            core.write_text('#!/bin/sh\nprintf "%s\\n" "not-json-private-secret"\n')
            core.chmod(0o700);nodes.write_text('invalid\n')
            run=subprocess.run([PW,'-NoProfile','-File',str(ROOT/'scripts/Test-Batch.ps1'),'-Nodes',str(nodes),'-Core',str(core),'-Curl','curl','-InspectOnly','-OutputDirectory',str(report)],text=True,capture_output=True,timeout=20)
            self.assertNotEqual(run.returncode,0)
            summary=json.loads((report/'summary.json').read_text())
            self.assertFalse(summary['completed'])
            self.assertEqual(summary['batch_error']['stage'],'INVENTORY')
            self.assertIsNone(summary['inventory_error'])
            for file in report.iterdir():
                self.assertNotIn('private-secret',file.read_text(encoding='utf-8-sig'))

if __name__=='__main__':unittest.main(verbosity=2)
