"""Independent Paramiko SSH direct-tcpip peer; never runs a remote command."""
import base64
import contextlib
import hashlib
import json
import pathlib
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from urllib.parse import quote
from test_core import BIN, exact, free_port
import paramiko


class ForwardOnly(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL if (username, password) == ('user', 'secret') else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        return paramiko.OPEN_SUCCEEDED if destination == ('echo.test', 443) else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class SSHReferenceTests(unittest.TestCase):
    @contextlib.contextmanager
    def pair(self, bad_pin=False, bad_password=False):
        key = paramiko.RSAKey.generate(2048)
        pin = 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
        if bad_pin:
            pin = 'SHA256:' + 'A' * 43
        listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(); listener.settimeout(.2)
        stop = threading.Event(); workers, transports, errors = [], [], []
        def handle(raw):
            transport = paramiko.Transport(raw); transports.append(transport)
            try:
                transport.add_server_key(key); transport.start_server(server=ForwardOnly())
                while transport.is_active() and not stop.is_set():
                    channel = transport.accept(.2)
                    if channel is None:
                        continue
                    with channel:
                        channel.settimeout(5)
                        while data := channel.recv(65535):
                            channel.sendall(data)
            except (OSError, EOFError, paramiko.SSHException):
                pass
            except BaseException as e:
                errors.append(e)
            finally:
                transport.close(); transport.join(timeout=4); raw.close()
        def accept():
            while not stop.is_set():
                try:
                    raw, _ = listener.accept()
                except (TimeoutError, OSError):
                    continue
                w = threading.Thread(target=handle, args=(raw,)); workers.append(w); w.start()
        acceptor = threading.Thread(target=accept); acceptor.start()
        with tempfile.TemporaryDirectory(prefix='vpn-ssh-reference-') as temp:
            root = pathlib.Path(temp); port = free_port()
            uri = f'ssh://user:{"wrong" if bad_password else "secret"}@127.0.0.1:{listener.getsockname()[1]}?hostkey={quote(pin, safe="")}'
            profile = {'listen_port': port, 'outbounds': [{'tag': 'ssh', 'uri': uri}], 'final': 'ssh'}
            path = root / 'profile.json'; path.write_text(json.dumps(profile), encoding='utf-8')
            with (root / 'core.log').open('w') as log:
                process = subprocess.Popen([str(BIN), '--config', str(path)], stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 6
                    while True:
                        if process.poll() is not None:
                            self.fail('core exited before readiness')
                        try:
                            with socket.create_connection(('127.0.0.1', port), .2):
                                break
                        except OSError:
                            if time.monotonic() > deadline:
                                self.fail('SOCKS readiness timeout')
                            time.sleep(.03)
                    yield port
                    self.assertEqual(errors, [])
                except BaseException as error:
                    log.flush(); error.add_note((root / 'core.log').read_text(errors='replace')[-3000:]); raise
                finally:
                    if process.poll() is None:
                        process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill(); process.wait(timeout=3)
                    stop.set(); listener.close(); acceptor.join(timeout=3)
                    for t in transports: t.close()
                    for w in workers:
                        w.join(timeout=6); self.assertFalse(w.is_alive(), 'SSH peer worker survived shutdown')
                    self.assertFalse(acceptor.is_alive())

    def connect(self, port):
        c = socket.create_connection(('127.0.0.1', port), 5); c.settimeout(5)
        c.sendall(b'\x05\x01\x00'); self.assertEqual(exact(c, 2), b'\x05\x00')
        c.sendall(b'\x05\x01\x00\x03\x09echo.test\x01\xbb')
        reply = exact(c, 4)
        if reply[3] == 1:
            exact(c, 6)
        elif reply[3] == 4:
            exact(c, 18)
        else:
            exact(c, exact(c, 1)[0] + 2)
        return c, reply[1]

    def test_independent_ssh_payload_and_repeated_close(self):
        with self.pair() as port:
            for cycle in range(16):
                c, code = self.connect(port)
                with c:
                    self.assertEqual(code, 0)
                    body = b'independent Paramiko direct-tcpip\x00\xff' * 128
                    c.sendall(body); self.assertEqual(exact(c, len(body)), body)

    def test_independent_auth_and_host_identity_rejection(self):
        for bad_pin, bad_password in [(True, False), (False, True)]:
            with self.subTest(bad_pin=bad_pin, bad_password=bad_password), self.pair(bad_pin, bad_password) as port:
                c, code = self.connect(port)
                with c:
                    self.assertNotEqual(code, 0)

    def test_independent_client_against_core_server_password_and_public_key(self):
        host_key=paramiko.RSAKey.generate(2048);authorized=paramiko.RSAKey.generate(2048)
        for public_key in [False,True]:
            with self.subTest(public_key=public_key),tempfile.TemporaryDirectory(prefix='vpn-ssh-server-reference-') as temp,socket.socket() as echo:
                root=pathlib.Path(temp);host_path=root/'host-key';host_key.write_private_key_file(str(host_path));authorized_path=root/'authorized_keys';authorized_path.write_text(authorized.get_name()+' '+authorized.get_base64()+'\n',encoding='ascii')
                echo.bind(('127.0.0.1',0));echo.listen();echo.settimeout(.2);stop=threading.Event();workers=[]
                def handle(c):
                    try:
                        with c:
                            c.settimeout(3)
                            while data:=c.recv(65535):c.sendall(data)
                    except OSError:pass
                def accept():
                    while not stop.is_set():
                        try:c,_=echo.accept()
                        except OSError:continue
                        w=threading.Thread(target=handle,args=(c,));workers.append(w);w.start()
                listener=threading.Thread(target=accept);listener.start();port=free_port();options={'username':'user'}
                if public_key:options['authorized-keys']=str(authorized_path)
                spec={'protocol':'ssh','listen':f'127.0.0.1:{port}','key_file':str(host_path),'options':options}
                if not public_key:spec['password']='secret'
                profile={'outbounds':[{'tag':'direct','uri':'direct://'}],'final':'direct','inbounds':[spec]};config=root/'server.json';config.write_text(json.dumps(profile),encoding='utf-8')
                with (root/'project.log').open('w') as log:
                    process=subprocess.Popen([str(BIN),'--config',str(config),'--no-socks'],stdout=log,stderr=log);transports=[]
                    try:
                        deadline=time.monotonic()+6
                        while True:
                            if process.poll() is not None:self.fail('SSH core server exited before readiness')
                            try:
                                with socket.create_connection(('127.0.0.1',port),.2):break
                            except OSError:
                                if time.monotonic()>deadline:self.fail('SSH listener readiness timeout')
                                time.sleep(.03)
                        for cycle in range(16):
                            transport=paramiko.Transport(('127.0.0.1',port));transports.append(transport)
                            transport.connect(hostkey=host_key,username='user',password=None if public_key else 'secret',pkey=authorized if public_key else None)
                            with transport.open_channel('direct-tcpip',echo.getsockname(),('192.0.2.99',4444)) as channel:
                                channel.settimeout(4);body=b'Independent SSH server payload\x00\xff'*512;channel.sendall(body);self.assertEqual(exact(channel,len(body)),body)
                            with self.assertRaises(paramiko.SSHException):transport.open_session(timeout=2)
                            transport.close();transport.join(timeout=3);self.assertFalse(transport.is_alive())
                        bad=paramiko.Transport(('127.0.0.1',port));transports.append(bad)
                        with self.assertRaises(paramiko.AuthenticationException):bad.connect(hostkey=host_key,username='user',password='wrong')
                    except BaseException as error:
                        log.flush();error.add_note((root/'project.log').read_text(errors='replace')[-2500:]);raise
                    finally:
                        for transport in transports:transport.close();transport.join(timeout=3);self.assertFalse(transport.is_alive())
                        if process.poll() is None:process.terminate()
                        try:process.wait(timeout=5)
                        except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
                        stop.set();listener.join(timeout=2)
                        for w in workers:w.join(timeout=4);self.assertFalse(w.is_alive())
                        self.assertFalse(listener.is_alive())
