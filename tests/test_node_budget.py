"""Independent curl peers and a controlled clock prove the shared URL budget."""
import datetime
import importlib.util
import pathlib
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('node_budget_runner',ROOT/'scripts/Test-Nodes.py')
runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)


class Clock:
    def __init__(self):self.now=0
    def monotonic(self):return self.now


class NodeBudgetTests(unittest.TestCase):
    def run_probes(self,responses,timeout=10,url=None):
        clock=Clock();calls=[]
        def invoke(command,**kwargs):
            calls.append((command,kwargs))
            code,status,elapsed=responses[len(calls)-1]
            if code is None:
                clock.now+=kwargs['timeout']
                raise subprocess.TimeoutExpired(command,kwargs['timeout'],stderr=b'PRIVATE-STDERR')
            clock.now+=elapsed
            return subprocess.CompletedProcess(command,code,f'{status:03d}|0|{elapsed}|0|0|0|1|0',
                'wrong version number PRIVATE-STDERR' if code==35 else '')
        args=types.SimpleNamespace(timeout=timeout,url=url,curl_cacert=None)
        targets=runner.verification_targets(args)
        with tempfile.TemporaryDirectory() as td, mock.patch.object(runner.time,'monotonic',clock.monotonic), mock.patch.object(runner.subprocess,'run',invoke):
            result=runner.probe_targets(args,'curl',12345,pathlib.Path(td),targets)
        return result,calls

    def test_default_order_and_one_ten_second_budget(self):
        result,calls=self.run_probes([(None,0,0)]*3)
        self.assertEqual([c[0][-1] for c in calls],[url for _,url in runner.DEFAULT_TARGETS])
        self.assertEqual([p['endpoint'] for p in result['probe_attempts']],['example','google','microsoft'])
        self.assertAlmostEqual(sum(c[1]['timeout'] for c in calls),10)
        self.assertAlmostEqual(result['network_duration_ms'],10000)
        for command,kwargs in calls:
            self.assertLess(float(command[command.index('--max-time')+1]),10/3)
            self.assertAlmostEqual(kwargs['timeout'],10/3)
        self.assertEqual(result['curl_reason_code'],'CURL_EXIT_UNAVAILABLE')
        self.assertIsNone(result['curl_exit_code'])

    def test_fast_failure_then_success_skips_last_url_and_unused_time(self):
        result,calls=self.run_probes([(35,0,.05),(0,204,.1)])
        self.assertEqual(len(calls),2)
        self.assertEqual(result['status'],'PASS')
        self.assertEqual(result['success_endpoint'],'google')
        self.assertEqual(result['request_scheme'],'http')
        self.assertEqual(result['network_duration_ms'],150)
        self.assertEqual(result['curl_exit_code'],0)
        self.assertEqual(result['probe_attempts'][0]['curl_exit_code'],35)
        self.assertEqual(result['probe_attempts'][0]['curl_tls_error_class'],'TLS_RECORD_VERSION')
        self.assertNotIn('PRIVATE',str(result))

    def test_expired_global_deadline_starts_no_late_request(self):
        args=types.SimpleNamespace(timeout=10,curl_cacert=None)
        with tempfile.TemporaryDirectory() as td,mock.patch.object(runner.time,'monotonic',side_effect=[0,10,10]),mock.patch.object(runner.subprocess,'run') as process:
            result=runner.probe_targets(args,'curl',12345,pathlib.Path(td),runner.DEFAULT_TARGETS)
        process.assert_not_called()
        self.assertEqual(result['status'],'FAIL')
        self.assertEqual(result['curl_wait_reason'],'NETWORK_BUDGET_EXHAUSTED')
        self.assertIsNone(result['curl_exit_code'])
        self.assertEqual(result['probe_attempts'],[])

    def test_every_winner_stops_the_sequence_and_all_2xx_remain_valid(self):
        for winner in range(3):
            for status in (200,202,204,206,299):
                with self.subTest(winner=winner,status=status):
                    result,calls=self.run_probes([(0,503,.01)]*winner+[(0,status,.02)])
                    self.assertEqual(len(calls),winner+1)
                    self.assertEqual(result['success_endpoint'],runner.DEFAULT_TARGETS[winner][0])
                    self.assertEqual(result['status'],'PASS')
                    self.assertEqual(result['http_status'],status)

    def test_bad_certificate_and_bad_http_are_not_success(self):
        result,_=self.run_probes([(60,200,.01),(0,404,.01),(0,503,.01)])
        self.assertEqual(result['status'],'FAIL')
        self.assertEqual(result['curl_exit_code'],60)
        self.assertEqual(result['success_endpoint'],'')
        self.assertEqual([p['status'] for p in result['probe_attempts']],['FAIL']*3)
        self.assertEqual([p['http_status'] for p in result['probe_attempts']],[200,404,503])

    def test_process_start_failure_is_runner_failure_not_node_failure(self):
        args=types.SimpleNamespace(timeout=10,curl_cacert=None)
        with tempfile.TemporaryDirectory() as td,mock.patch.object(runner.subprocess,'run',side_effect=OSError('PRIVATE')):
            result=runner.probe_targets(args,'curl',12345,pathlib.Path(td),runner.DEFAULT_TARGETS)
        self.assertEqual(result['status'],'RUNNER_FAILED')
        self.assertEqual(len(result['probe_attempts']),1)
        self.assertNotIn('PRIVATE',str(result))

    def test_https_security_and_custom_url_compatibility(self):
        result,calls=self.run_probes([(0,200,.01)],url='https://localhost/private-target')
        command,kwargs=calls[0]
        self.assertEqual(result['success_endpoint'],'custom')
        self.assertEqual(command[1],'--disable')
        self.assertNotIn('--insecure',command)
        self.assertEqual(command[command.index('--proto')+1],'=https')
        self.assertEqual(command[command.index('--proto-redir')+1],'=https')
        self.assertEqual(command[command.index('--proxy')+1],'socks5h://127.0.0.1:12345')
        self.assertEqual(kwargs['timeout'],10)
        self.assertNotIn('private-target',str(result))
        for url in ('http://localhost/','https://user:secret@localhost/','https://localhost/\n'):
            with self.subTest(url=url),self.assertRaises(ValueError):
                runner.verification_targets(types.SimpleNamespace(url=url))


def exact(sock,size):
    output=b''
    while len(output)<size:
        part=sock.recv(size-len(output))
        if not part:raise OSError('Peer closed')
        output+=part
    return output


class SocksOrigin:
    """Route actual curl requests only into local independent HTTP/TLS peers."""
    def __init__(self,context,actions):
        self.context=context;self.actions=actions;self.requests=[];self.errors=[]
        self.stop=threading.Event();self.workers=[]
        self.server=socket.socket();self.server.bind(('127.0.0.1',0));self.server.listen(8)
        self.server.settimeout(.05);self.port=self.server.getsockname()[1]
        self.thread=threading.Thread(target=self.accept);self.thread.start()

    def accept(self):
        while not self.stop.is_set():
            try:client,_=self.server.accept()
            except socket.timeout:continue
            except OSError:return
            worker=threading.Thread(target=self.serve,args=(client,));self.workers.append(worker);worker.start()

    def serve(self,client):
        try:
            with client:
                client.settimeout(2)
                greeting=exact(client,2);self.assert_greeting(greeting)
                exact(client,greeting[1]);client.sendall(b'\x05\x00')
                header=exact(client,4)
                if header!=b'\x05\x01\x00\x03':raise ValueError('Expected SOCKS5 remote DNS CONNECT')
                host=exact(client,exact(client,1)[0]).decode('ascii')
                port=int.from_bytes(exact(client,2),'big')
                client.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
                stream=self.context.wrap_socket(client,server_side=True) if port==443 else client
                with stream:
                    request=b''
                    while b'\r\n\r\n' not in request:
                        request+=exact(stream,1)
                        if len(request)>16384:raise ValueError('Oversized HTTP request')
                    self.requests.append(host)
                    status,delay=self.actions[host]
                    if self.stop.wait(delay):return
                    location=b'Location: http://connectivitycheck.gstatic.com/generate_204\r\n' if status==302 else b''
                    stream.sendall(f'HTTP/1.1 {status} Fixture\r\nContent-Length: 0\r\nConnection: close\r\n'.encode()+location+b'\r\n')
        except (OSError,ssl.SSLError):pass  # Expected for timeout/certificate rejection.
        except Exception as error:self.errors.append(repr(error))

    @staticmethod
    def assert_greeting(greeting):
        if greeting[0]!=5 or not greeting[1]:raise ValueError('Invalid SOCKS greeting')

    def close(self):
        self.stop.set();self.server.close();self.thread.join(2)
        for worker in self.workers:worker.join(2)


@unittest.skipUnless(shutil.which('curl'),'Real curl is required')
class NodeBudgetWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes,serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        cls.temp=tempfile.TemporaryDirectory();cls.folder=pathlib.Path(cls.temp.name)
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Independent budget peer')])
        now=datetime.datetime.now(datetime.timezone.utc)
        certificate=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(days=1))
            .not_valid_after(now+datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('example.com'),x509.DNSName('www.microsoft.com')]),critical=False)
            .sign(key,hashes.SHA256()))
        cls.cert=cls.folder/'cert.pem';cls.key=cls.folder/'key.pem'
        cls.cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        cls.key.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption()))
        cls.context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);cls.context.load_cert_chain(cls.cert,cls.key)

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def probe(self,actions,timeout=10,trust=True):
        origin=SocksOrigin(self.context,actions)
        args=types.SimpleNamespace(timeout=timeout,curl_cacert=self.cert if trust else None)
        try:
            with tempfile.TemporaryDirectory() as td:
                started=time.monotonic()
                result=runner.probe_targets(args,shutil.which('curl'),origin.port,pathlib.Path(td),runner.DEFAULT_TARGETS)
                elapsed=time.monotonic()-started
            self.assertEqual(origin.errors,[])
            return result,origin.requests[:],elapsed
        finally:origin.close()

    def test_real_https_success_finishes_immediately_and_skips_fallbacks(self):
        result,requests,elapsed=self.probe({'example.com':(200,0)})
        self.assertEqual(result['status'],'PASS')
        self.assertEqual(requests,['example.com'])
        self.assertEqual(result['curl_ssl_verify_result'],0)
        self.assertLess(elapsed,2)

    def test_real_three_endpoint_failures_then_last_success(self):
        result,requests,elapsed=self.probe({'example.com':(503,0),'connectivitycheck.gstatic.com':(503,0),'www.microsoft.com':(200,0)})
        self.assertEqual(result['success_endpoint'],'microsoft')
        self.assertEqual([p['http_status'] for p in result['probe_attempts']],[503,503,200])
        self.assertEqual(requests,['example.com','connectivitycheck.gstatic.com','www.microsoft.com'])
        self.assertLess(elapsed,2)

    def test_real_bad_certificate_is_retained_before_http_204_success(self):
        result,requests,_=self.probe({'connectivitycheck.gstatic.com':(204,0)},trust=False)
        self.assertEqual(result['probe_attempts'][0]['curl_exit_code'],60)
        self.assertEqual(result['success_endpoint'],'google')
        self.assertEqual(result['request_scheme'],'http')
        self.assertEqual(result['http_status'],204)
        self.assertEqual(requests,['connectivitycheck.gstatic.com'])

    def test_real_https_redirect_cannot_downgrade_to_http(self):
        result,requests,_=self.probe({'example.com':(302,0),'connectivitycheck.gstatic.com':(204,0)})
        self.assertNotEqual(result['probe_attempts'][0]['curl_exit_code'],0)
        self.assertEqual(requests,['example.com','connectivitycheck.gstatic.com'])
        self.assertEqual(result['success_endpoint'],'google')

    def test_real_timeouts_share_one_deadline_and_preserve_curl_28(self):
        result,requests,elapsed=self.probe({name:(200,2) for name in ('example.com','connectivitycheck.gstatic.com','www.microsoft.com')},timeout=1.5)
        self.assertEqual(result['status'],'FAIL')
        self.assertEqual(len(requests),3)
        self.assertEqual([p['curl_exit_code'] for p in result['probe_attempts']],[28,28,28])
        self.assertLess(elapsed,1.65)
        self.assertGreater(elapsed,1.1)


if __name__=='__main__':unittest.main()
