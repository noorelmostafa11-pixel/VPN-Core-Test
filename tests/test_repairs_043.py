"""Observed header rejection and native TLS diagnostic regressions."""
import json,subprocess,unittest
from test_repairs_042 import PROBE

class RepositoryRepairTests(unittest.TestCase):
    def probe(self,**values):
        r=subprocess.run([PROBE],input=json.dumps(values)+'\n',text=True,capture_output=True,check=True)
        return json.loads(r.stdout)

    def test_opaque_repeated_response_fields_are_preserved(self):
        fields=[['x-trace','first'],['x-trace','second'],['etag','opaque-a'],['etag','opaque-b']]
        text='HTTP/1.1 101 OK\r\n'+'\r\n'.join(k+': '+v for k,v in fields)
        r=self.probe(op='headers',text=text)
        self.assertNotIn('error',r)
        self.assertEqual(r['fields'],fields)

    def test_critical_duplicate_cannot_hide_in_opaque_fields(self):
        r=self.probe(op='headers',text='HTTP/1.1 101 OK\r\nX-Trace: a\r\nX-Trace: b\r\nSec-WebSocket-Accept: first\r\nsec-websocket-accept: second')
        self.assertEqual(r['reason_code'],'HTTP_HEADER_DUPLICATE')

    def test_native_hresult_is_classified_without_guessing_peer_data(self):
        cases={0x80090322:'TLS_CERTIFICATE_NAME',0x80090325:'TLS_CERTIFICATE_UNTRUSTED',0x80090328:'TLS_CERTIFICATE_VALIDITY',0x80090326:'TLS_HANDSHAKE_MESSAGE',0x80090367:'TLS_ALPN_NEGOTIATION',0x00090320:'TLS_CLIENT_CERTIFICATE_REQUIRED',0xDEADBEEF:'TLS_HANDSHAKE_VERIFY'}
        for status,reason in cases.items():
            with self.subTest(status=hex(status)):
                r=self.probe(op='native-reason',status=status)
                self.assertEqual(r['reason_code'],reason)
                self.assertEqual(r['native_status'],status)

if __name__=='__main__':unittest.main(verbosity=2)
