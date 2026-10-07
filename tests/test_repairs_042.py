"""Regression cases for real observed failures, with synthetic credentials."""
import base64,hashlib,json,os,pathlib,subprocess,tempfile,unittest
from urllib.parse import quote,quote_plus
from test_core import ROOT,BIN
PROBE=os.environ.get('VPN_CORE_REPAIR_PROBE',str(ROOT/'bin/repair-probe'))
URI='vless://12345678-1234-4567-9234-567812345678@127.0.0.1:443?type=raw&security=none'
class RepairTests(unittest.TestCase):
    def probe(self,**value):
        r=subprocess.run([PROBE],input=json.dumps(value)+'\n',text=True,capture_output=True,check=True)
        return json.loads(r.stdout)
    def test_form_json_preserves_encoded_plus_and_credentials(self):
        extra={'headers':{'X-Test':'literal+plus'},'noGRPCHeader':True}
        uri='trojan://credential%2Bplus@localhost:443?type=xhttp&security=tls&mode=stream-one&extra='+quote_plus(json.dumps(extra))
        row=self.probe(op='config',uri=uri)
        self.assertNotIn('error',row);self.assertEqual(row['password_hash'],hashlib.sha224(b'credential+plus').hexdigest())
        # Literal plus in an enum is never reinterpreted as a form space.
        bad=self.probe(op='config',uri=URI.replace('type=raw','type=ws%2B'))
        self.assertEqual(bad['reason_code'],'TRANSPORT_NAME_INVALID')
    def test_enum_flow_empty_json_and_original_semantics(self):
        row=self.probe(op='config',uri=URI.replace('type=raw','type=ws+').replace('security=none','security=none+')+'&flow=none&fm=&extra=')
        self.assertNotIn('error',row);self.assertEqual(row['transport'],'websocket');self.assertEqual(row['security'],'none');self.assertEqual(row['flow'],'');self.assertEqual(row['original_flow'],'none');self.assertEqual(row['original_type'],'ws+')
        bad=self.probe(op='config',uri=URI+'&fm=%7B')
        self.assertIn('error',bad)
    def test_one_bounded_plugin_layer(self):
        plugin='v2ray-plugin;mode=websocket;host=localhost;path=/test;mux=0;skip-cert-verify=true;sni=legacy-display-name'
        uri='ss://'+base64.urlsafe_b64encode(b'aes-256-gcm:secret+unchanged').decode()+'@127.0.0.1:443?plugin='+quote(quote(plugin,safe=''),safe='')+';'
        row=self.probe(op='config',uri=uri);self.assertNotIn('error',row);self.assertEqual(row['plugin'],'v2ray-plugin');self.assertFalse(row['plugin_mux']);self.assertEqual(row['path'],'/test');self.assertTrue(row['certificate_verification']);self.assertTrue(row['legacy_insecure_requested'])
        bad=self.probe(op='config',uri=uri.replace('mux%253D0','mux%253Dinvalid'))
        self.assertIn('error',bad)
    def test_alpn_respects_explicit_choices(self):
        row=self.probe(op='config',uri=URI.replace('type=raw&security=none','type=ws&security=tls')+'&alpn=h2,http%2F1.1')
        self.assertEqual(row['alpn'],['h2','http/1.1']);self.assertEqual(row['selected_alpn'],['http/1.1'])
        row=self.probe(op='config',uri=URI.replace('type=raw&security=none','type=httpupgrade&security=tls')+'&alpn=h2')
        self.assertEqual(row['alpn_configuration_reason_code'],'ALPN_CARRIER_INCOMPATIBLE');self.assertEqual(row['selected_alpn'],['h2']);self.assertTrue(row['connectable_by_this_build'])
    def test_headers_list_cookie_and_critical_rejection(self):
        row=self.probe(op='headers',text='HTTP/1.1 101 OK\r\nConnection: keep-alive\r\nConnection: Upgrade\r\nSet-Cookie: a=one\r\nSet-Cookie: b=two')
        self.assertEqual(row['cookies'],['a=one','b=two']);self.assertEqual(row['connection'],'keep-alive, Upgrade')
        row=self.probe(op='headers',text='HTTP/1.1 101 OK\r\nConnection: keep-alive,\tUpgrade');self.assertEqual(row['connection'],'keep-alive,\tUpgrade')
        for name in ['Content-Length','Transfer-Encoding','Host','Sec-WebSocket-Accept','Upgrade']:
            with self.subTest(name=name):
                row=self.probe(op='headers',text=f'HTTP/1.1 200 OK\r\n{name}: one\r\n{name}: two')
                self.assertEqual(row['reason_code'],'HTTP_HEADER_DUPLICATE')
    def test_invalid_path_retains_parsed_features_and_original_id(self):
        uri=URI.replace('type=raw','type=ws')+'&path=%00'
        with tempfile.TemporaryDirectory() as td:
            file=pathlib.Path(td)/'nodes.txt';file.write_text(uri+'\n')
            result=subprocess.run([BIN,'--inspect-list',str(file)],text=True,capture_output=True,check=True)
            row=json.loads(result.stdout);self.assertTrue(row['uri_parsed']);self.assertFalse(row['config_valid']);self.assertFalse(row['parsed']);self.assertEqual(row['protocol'],'vless');self.assertEqual(row['transport'],'websocket');self.assertEqual(row['reason_code'],'HTTP_PATH_INVALID');self.assertEqual(row['node_id'],hashlib.sha256(uri.encode()).hexdigest()[:20])
    def test_protocol_auth_and_nonce_classes(self):
        row=self.probe(op='decode',uri=URI,data=base64.b64encode(b'\1\0').decode());self.assertEqual(row['reason_code'],'VLESS_RESPONSE_VERSION')
        ss='ss://'+base64.b64encode(b'chacha20-ietf-poly1305:synthetic').decode()+'@localhost:443?security=none'
        row=self.probe(op='decode',uri=ss,data=base64.b64encode(bytes(50)).decode());self.assertEqual(row['reason_code'],'SS_RESPONSE_LENGTH_AUTH')
        row=self.probe(op='nonce');self.assertEqual(row['reason_code'],'SS_NONCE_EXHAUSTED')
    def test_ss2022_keys_are_validated_before_network(self):
        uri='ss://2022-blake3-aes-128-gcm:not-a-valid-key@localhost:443?security=none'
        row=self.probe(op='config',uri=uri);self.assertEqual(row['reason_code'],'SS2022_PSK_LENGTH')

if __name__=='__main__':unittest.main(verbosity=2)
