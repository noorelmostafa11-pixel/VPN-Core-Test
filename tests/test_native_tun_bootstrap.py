"""Metadata/policy union regressions without touching parser or input URIs."""
import ctypes as c,json,os,pathlib,socket,sys,tempfile,unittest
from urllib.parse import quote
import test_core as core
ROOT=core.ROOT;sys.path.insert(0,str(ROOT/'sdk/native'));sys.path.insert(0,str(ROOT/'sdk/linux'))
from tun_host import TunHost
BUILD=pathlib.Path(os.environ.get('VPN_NATIVE_BUILD',ROOT/'build/linux-amd64'))
ID='00112233-4455-6677-8899-aabbccddeeff'
class BootstrapTests(unittest.TestCase):
    def targets(self,query):
        with tempfile.TemporaryDirectory() as td:
            path=pathlib.Path(td)/'node.ini';uri=f'vless://{ID}@primary.test:443?security=tls&type=xhttp&'+query
            path.write_text('node_uri='+uri+'\n')
            host=TunHost(BUILD,path,protect=lambda _:True,resolve=lambda _:['127.0.0.1'])
            targets=host.bootstrap_targets()
            self.assertEqual(path.read_text(),'node_uri='+uri+'\n')
            self.assertEqual(host.core.vpn_core_bootstrap_targets(host.config,None,1),-len(json.dumps(targets,separators=(',',':'),sort_keys=True).encode())-1)
            return targets
    def test_primary_literal_ech_never_adds_network_endpoint(self):
        self.assertEqual(self.targets('ech=AAQAAAE='),[{'host':'primary.test','port':443}])
    def test_separate_download_same_ip_and_distinct_ports(self):
        extra={'downloadSettings':{'address':'primary.test','port':8443}}
        self.assertEqual(self.targets('extra='+quote(json.dumps(extra))),[{'host':'primary.test','port':443},{'host':'primary.test','port':8443}])
    def test_download_hostname_and_own_ech_bootstrap(self):
        extra={'DownloadSettings':{'Address':'download.test','Port':8443,'Security':'tls','TLSSettings':{'ECHConfigList':'cdn.test+https://resolver.test:444/dns-query'}}}
        self.assertEqual(self.targets('extra='+quote(json.dumps(extra))),[{'host':'primary.test','port':443},{'host':'download.test','port':8443},{'host':'resolver.test','port':444}])
    def test_ech_schemes_ipv6_and_inherited_download(self):
        for url,target in [('udp://resolver.test',('resolver.test',53)),('tcp://resolver.test:5353',('resolver.test',5353)),('tls://[2001:db8::53]',('2001:db8::53',853)),('https://resolver.test/dns-query',('resolver.test',443))]:
            extra={'downloadSettings':{'port':8443}}
            rows=self.targets('ech='+quote('name.test '+url)+'&extra='+quote(json.dumps(extra)))
            self.assertEqual(rows,[{'host':'primary.test','port':443},{'host':target[0],'port':target[1]},{'host':'primary.test','port':8443}])
    @unittest.skipIf(os.name=='nt','Linux nft syntax unit check')
    def test_linux_policy_keeps_all_exact_bootstrap_ports(self):
        import native_tun
        from unittest.mock import patch
        captured=[]
        class Absent:returncode=1
        policy=native_tun.LinuxPolicy('vpntest',['192.0.2.9'],443,endpoints=[('192.0.2.9',443),('192.0.2.9',8443),('2001:db8::53',853)])
        with patch.object(native_tun.subprocess,'run',return_value=Absent()),patch.object(native_tun,'command',side_effect=lambda *a,**k:captured.append(k.get('input',''))):policy.acquire()
        text=captured[0]
        for dest,port in [('192.0.2.9',443),('192.0.2.9',8443),('2001:db8::53',853)]:self.assertIn(f'daddr {dest} meta mark {native_tun.MARK} meta l4proto {{ tcp, udp }} th dport {port} accept',text)
        self.assertIn('policy drop',text);self.assertNotIn('th dport 53 accept',text)
if __name__=='__main__':unittest.main()
