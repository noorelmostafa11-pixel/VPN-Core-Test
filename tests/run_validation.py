"""Explicit suites avoid collecting imported TestCase classes a second time."""
import argparse,unittest
parser=argparse.ArgumentParser();parser.add_argument('--no-batch',action='store_true');args=parser.parse_args()
names=['test_repairs_043.RepositoryRepairTests','test_repairs_042.RepairTests','test_repair_transport_042.RepairTransportTests','test_core.CoreTests','test_expanded.ExpandedTests','test_expansion_030.ExpansionTests','test_pre_expansion.PreExpansionTests','test_tls_profiles.TLSProfileTests','test_reality.RealityTests','test_ech.ECHTests','test_vision.VisionTests','test_ws_plugins.WebSocketPluginTests','test_xhttp_modes.XHttpTests','test_vless_encryption.VlessEncryptionTests','test_legacy_xtls.LegacyXTLSTests','test_mkcp.MKCPTests']
if not args.no_batch:names+=['test_repair_batch_043.RepositoryBatchRepairTests','test_repair_batch_042.RepairBatchTests','test_batch.BatchTests','test_batch_expansion_030.ExpandedBatchTests','test_batch_exitcode.BatchExitCodeTests','test_batch_pre_expansion.PreBatchTests']
result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromNames(names))
raise SystemExit(0 if result.wasSuccessful() else 1)
