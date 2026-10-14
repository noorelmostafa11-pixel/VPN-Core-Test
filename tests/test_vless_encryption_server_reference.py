"""Pinned official Xray hybrid client against project-owned server records."""
import base64
import subprocess
import unittest

from cryptography.hazmat.primitives.asymmetric import x25519
import test_server_reference as serverref
import test_vless_server_reference as visionref


class VLESSEncryptionServerReferenceTests(unittest.TestCase):
    setUpClass = classmethod(serverref.ServerReferenceTests.setUpClass.__func__)
    tearDownClass = classmethod(serverref.ServerReferenceTests.tearDownClass.__func__)
    socks = serverref.ServerReferenceTests.socks
    wait_port = serverref.ServerReferenceTests.wait_port
    reference_pair = serverref.ServerReferenceTests.reference_pair
    payload_cases = visionref.VLESSVisionReferenceTests.payload_cases

    def test_xray_hybrid_modes_tickets_static_kem_and_vision(self):
        private = x25519.X25519PrivateKey.generate()
        xsecret = base64.urlsafe_b64encode(private.private_bytes_raw()).decode().rstrip('=')
        xpublic = base64.urlsafe_b64encode(private.public_key().public_bytes_raw()).decode().rstrip('=')
        # Synthetic seed only. Independent official CLI derives its public KEM
        # offer, without importing project server/handshake implementation.
        seed = base64.urlsafe_b64encode(bytes(range(64))).decode().rstrip('=')
        generated = subprocess.check_output([str(self.xray), 'mlkem768', '-i', seed], text=True)
        public = next(line.split(':', 1)[1].strip() for line in generated.splitlines() if line.startswith('Client'))
        self.assertEqual(len(base64.urlsafe_b64decode(public + '=' * (-len(public) % 4))), 1184)
        for mode, rtt, secure, flow, kem, reality in [
            ('native', '1rtt', False, '', False, False),
            ('xorpub', '0rtt', False, 'xtls-rprx-vision', True, False),
            ('random', '0rtt', False, 'xtls-rprx-vision', True, False),
            ('native', '0rtt', True, 'xtls-rprx-vision', False, False),
            ('random', '0rtt', True, 'xtls-rprx-vision', False, False),
            ('native', '0rtt', True, 'xtls-rprx-vision', False, True),
        ]:
            with self.subTest(mode=mode, rtt=rtt, tls=secure, flow=flow, kem=kem, reality=reality):
                secret_keys = [xsecret, seed] if kem else [xsecret]
                public_keys = [xpublic, public] if kem else [xpublic]
                decryption = '.'.join(['mlkem768x25519plus', mode, '60-60s', '100-75-75', *secret_keys])
                encryption = '.'.join(['mlkem768x25519plus', mode, rtt, '100-75-75', *public_keys])
                self.payload_cases(flow=flow, secure=secure, use_reality=reality, decryption=decryption, encryption=encryption)


if __name__ == '__main__':
    unittest.main(verbosity=2)
