"""Run independent wire oracles against the source-built Go core."""
import argparse,os,pathlib,subprocess,sys,unittest,shutil
ROOT=pathlib.Path(__file__).resolve().parents[1]
if os.name=='nt' and not shutil.which('openssl'):
 git_tools=pathlib.Path(os.environ.get('ProgramFiles','C:/Program Files'))/'Git/usr/bin'
 if (git_tools/'openssl.exe').exists():os.environ['PATH']=str(git_tools)+os.pathsep+os.environ['PATH']
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--skip-build',action='store_true');p.add_argument('--binary',type=pathlib.Path);a=p.parse_args()
binary=(a.binary or ROOT/'bin'/('vpn-core.exe' if os.name=='nt' else 'vpn-core')).resolve();suffix='.exe' if os.name=='nt' else '';(ROOT/'bin').mkdir(exist_ok=True)
def build(output,source,tags=None):subprocess.run(['go','build','-mod=vendor',*(['-tags',tags] if tags else []),'-o',str(ROOT/'bin'/(output+suffix)),source],cwd=ROOT,check=True)
if not a.skip_build:
 build('vpn-core','./cmd/vpn-core')
 for name,file in [('xhttp-peer','xhttp_peer.go'),('ech-peer','ech_peer.go'),('quic-peer','quic_peer.go'),('vless-encryption-peer','vless_encryption_peer.go'),('mldsa-signer','mldsa_signer.go')]:build(name,'tests/'+file)
 for name in ['crypto-probe','protocol-probe','uri-source-probe']:build(name,'./cmd/test-probe','testprobe')
os.environ['QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING']='true'
os.environ['PYTHONUTF8']='1'
os.environ['VPN_CORE_TEST_BINARY']=str(binary);sys.path.insert(0,str(ROOT/'tests'))
names=['test_core.CoreTests','test_expanded.ExpandedTests','test_pre_expansion.PreExpansionTests','test_reality.RealityTests','test_vision.VisionTests','test_legacy_xtls.LegacyXTLSTests','test_ws_plugins.WebSocketPluginTests','test_xhttp_modes.XHttpTests','test_mkcp.MKCPTests','test_ech.ECHTests','test_quic_carrier.QUICCarrierTests','test_support_additions.SupportAdditionTests','test_vless_encryption.VlessEncryptionTests','test_udp_sdk.UdpSdkTests','test_uri_compatibility.UriCompatibilityTests','test_compat_repairs.CompatibilityRepairTests','test_repair_transport_042.RepairTransportTests']
suite=unittest.defaultTestLoader.loadTestsFromNames(names)
suite.addTests(unittest.defaultTestLoader.loadTestsFromName('test_server_reference.ServerReferenceTests'))
suite.addTests(unittest.defaultTestLoader.loadTestsFromName('test_ss_server_reference.SSServerReferenceTests'))
suite.addTests(unittest.defaultTestLoader.loadTestsFromName('test_hysteria_reference.HysteriaReferenceTests'))
suite.addTests(unittest.defaultTestLoader.loadTestsFromName('test_hysteria1_reference.Hysteria1ReferenceTests'))
suite.addTests(unittest.defaultTestLoader.loadTestsFromName('test_ssh_reference.SSHReferenceTests'))
suite.addTests(unittest.defaultTestLoader.loadTestsFromName('test_wireguard_reference.WireGuardReferenceTests'))
suite.addTests(unittest.defaultTestLoader.loadTestsFromName('test_anytls_reference.AnyTLSReferenceTests'))
suite.addTests(unittest.defaultTestLoader.loadTestsFromName('test_tuic_reference.TUICReferenceTests'))
suite.addTests(unittest.defaultTestLoader.loadTestsFromName('test_shadowtls_reference.ShadowTLSReferenceTests'))
result=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not result.wasSuccessful())
