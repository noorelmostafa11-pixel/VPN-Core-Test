"""Compare verified Internet bodies via SOCKS and in-memory Native IP packets.

Node URIs stay in a temporary local file and never enter reports. This tool does
not create a TUN adapter or change routes, DNS, firewall or installed packages.
"""
import argparse, contextlib, hashlib, http.client, io, ipaddress, json, os
import pathlib, shutil, socket, ssl, struct, subprocess, sys, tempfile, threading, time
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
from native_tun_client import PacketTCPClient
from test_native_tun_runtime import checksum, SRC

class InternetTCPClient(PacketTCPClient):
    def __init__(self, app, destination, target_port=443):
        self.destination = socket.inet_aton(destination)
        super().__init__(app,target_port)
    def _packet(self, payload, seq, ack, flags):
        packet = bytearray(super()._packet(payload, seq, ack, flags))
        packet[16:20] = self.destination
        packet[10:12] = b'\0\0'
        packet[36:38] = b'\0\0'
        packet[10:12] = struct.pack('!H', checksum(packet[:20]))
        packet[36:38] = struct.pack('!H', checksum(packet[12:20] + struct.pack('!BBH', 0, 6, len(packet)-20) + packet[20:]))
        return bytes(packet)

class TLSStream:
    def __init__(self, transport, hostname):
        self.transport = transport
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = ssl.create_default_context().wrap_bio(self.incoming, self.outgoing, server_hostname=hostname)
        self._drive(self.tls.do_handshake)
    def _flush(self):
        while self.outgoing.pending:
            self.transport.sendall(self.outgoing.read())
    def _drive(self, operation):
        while True:
            try:
                result = operation()
                self._flush()
                return result
            except ssl.SSLWantReadError:
                self._flush()
                data = self.transport.recv(65536)
                if data: self.incoming.write(data)
                else: self.incoming.write_eof()
            except ssl.SSLWantWriteError:
                self._flush()
    def sendall(self, data):
        position = 0
        while position < len(data):
            position += self._drive(lambda: self.tls.write(data[position:]))
    def recv(self, size):
        try: return self._drive(lambda: self.tls.read(size))
        except (ssl.SSLZeroReturnError, ssl.SSLEOFError): return b''
    def makefile(self, mode):
        stream = self
        class Reader(io.RawIOBase):
            def readable(self): return True
            def readinto(self, buffer):
                data = stream.recv(len(buffer))
                buffer[:len(data)] = data
                return len(data)
        return io.BufferedReader(Reader())


def request(stream, hostname, path='/', marker=b'Example Domain', maximum=2097152):
    stream.sendall(('GET ' + path + ' HTTP/1.1\r\nHost: ' + hostname + '\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n').encode('ascii'))
    response = http.client.HTTPResponse(stream)
    response.begin()
    if response.length is not None and response.length > maximum:
        raise ValueError('HTTP body exceeds the test limit')
    expected_length=response.length
    body = response.read(maximum + 1)
    if expected_length is not None and len(body)!=expected_length:
        raise ValueError('HTTPS body was incomplete')
    if len(body) > maximum or not body or (marker and marker not in body):
        raise ValueError('HTTPS body verification failed')
    if response.status != 200:
        raise ValueError('HTTP status ' + str(response.status))
    response.close()
    return {'status': 'PASS', 'http_status': 200, 'body_bytes': len(body),
            'body_sha256': hashlib.sha256(body).hexdigest(), 'certificate_verified': True}


def exact(stream, length):
    result = b''
    while len(result) < length:
        data = stream.recv(length-len(result))
        if not data: raise EOFError('SOCKS reply incomplete')
        result += data
    return result


def socks_request(port, hostname, destination, path='/', marker=b'Example Domain'):
    with socket.create_connection(('127.0.0.1', port), 15) as raw:
        raw.sendall(b'\5\1\0')
        if exact(raw, 2) != b'\5\0': raise ValueError('SOCKS method rejected')
        try:
            address = ipaddress.ip_address(destination)
            target = bytes([1 if address.version == 4 else 4]) + address.packed
        except ValueError:
            name = destination.encode('idna')
            target = bytes([3, len(name)]) + name
        raw.sendall(b'\5\1\0' + target + b'\1\xbb')
        reply = exact(raw, 4)
        if reply[1] != 0: raise ConnectionError('SOCKS connection rejected')
        length = 4 if reply[3] == 1 else 16 if reply[3] == 4 else exact(raw, 1)[0]
        exact(raw, length + 2)
        with ssl.create_default_context().wrap_socket(raw, server_hostname=hostname) as tls:
            return request(tls, hostname, path, marker)


def udp_dns(port, resolver='9.9.9.9', qtype=1):
    destination = ipaddress.ip_address(resolver)
    source = SRC if destination.version == 4 else ipaddress.ip_address('fd71:5650::2').packed
    query = struct.pack('!HHHHHH', 0x5650, 0x0100, 1, 0, 0, 0) + b'\7example\3com\0' + struct.pack('!HH', qtype, 1)
    datagram = struct.pack('!HHHH', 35053, 53, len(query)+8, 0) + query
    pseudo = (source + destination.packed + (struct.pack('!BBH', 0, 17, len(datagram)) if destination.version == 4 else struct.pack('!I3xB', len(datagram), 17)))
    check = checksum(pseudo + datagram) or 65535
    datagram = datagram[:6] + struct.pack('!H', check) + datagram[8:]
    if destination.version == 4:
        header = struct.pack('!BBHHHBBH4s4s', 69, 0, len(datagram)+20, 0, 0, 64, 17, 0, source, destination.packed)
        packet = header[:10] + struct.pack('!H', checksum(header)) + header[12:] + datagram
    else:
        packet = struct.pack('!IHBB16s16s', 6 << 28, len(datagram), 17, 64, source, destination.packed) + datagram
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as app:
        app.connect(('127.0.0.1', port)); app.settimeout(6); app.send(packet)
        reply = app.recv(65535)
        offset = 20 if destination.version == 4 else 40
        if len(reply) < offset + 20 or reply[offset:offset+4] != struct.pack('!HH', 53, 35053):
            raise ValueError('DNS response endpoint mismatch')
        message = reply[offset+8:]
        transaction, flags, _, answers, _, _ = struct.unpack('!HHHHHH', message[:12])
        if transaction != 0x5650 or flags & 15 or not (flags & 0x8000) or answers == 0:
            raise ValueError('DNS response validation failed')
        app.send(b'STOP')
        return {'status': 'PASS', 'response_bytes': len(message), 'answers': answers}


def tcp_dns_gateway(port,resolver):
    app=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);app.connect(('127.0.0.1',port));client=None
    try:
        client=InternetTCPClient(app,resolver,53);client.settimeout(15)
        queries=[]
        for ident,qtype in ((0x5650,1),(0x5651,28)):
            query=struct.pack('!HHHHHH',ident,0x0100,1,0,0,0)+b'\7example\3com\0'+struct.pack('!HH',qtype,1)
            queries.append(struct.pack('!H',len(query))+query)
        client.sendall(b''.join(queries));answers=[]
        for ident in (0x5650,0x5651):
            message=exact(client,struct.unpack('!H',exact(client,2))[0])
            if len(message)<12 or struct.unpack('!H',message[:2])[0]!=ident or message[3]&15:raise ValueError('Pipelined TCP DNS reply invalid')
            answers.append(len(message))
        return {'status':'PASS','pipelined_queries':2,'response_bytes':answers}
    finally:
        if client:client.close()
        app.send(b'STOP');app.close()


@contextlib.contextmanager
def process(command, cwd):
    proc = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0)
    events = []
    condition = threading.Condition()
    def collect():
        for line in proc.stdout:
            if "diagnostic=" in line:line=line.split("diagnostic=",1)[1]
            try: event = json.loads(line)
            except (ValueError, TypeError): continue
            with condition: events.append(event); condition.notify_all()
    reader = threading.Thread(target=collect, daemon=True); reader.start()
    try: yield proc, events, condition
    finally:
        if proc.poll() is None:
            proc.terminate() # Both test processes own no OS adapter or network policy.
        proc.wait(timeout=10); reader.join(2)


def observe(operation):
    started = time.monotonic()
    try: result = operation()
    except Exception as error: result = {'status': 'FAIL', 'error_type': type(error).__name__, 'reason': str(error)[:240]}
    result['elapsed_seconds'] = round(time.monotonic()-started, 3)
    return result


def compile_gateway(build, destination, compiler):
    destination.mkdir(parents=True, exist_ok=True)
    executable = destination / ('packet-gateway.exe' if os.name == 'nt' else 'packet-gateway')
    flags = ['-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-misleading-indentation']
    libraries = ['-pthread']
    if os.name == 'nt':
        flags += ['-D_WIN32_WINNT=0x0A00', '-static', '-static-libgcc', '-static-libstdc++']
        libraries += ['-lws2_32', '-lsecur32', '-lcrypt32', '-lbcrypt']
    else: flags += ['-DVPN_CORE_PORTABLE']; libraries += ['-ldl']
    subprocess.run([compiler, *flags, str(ROOT/'tests/netstack_packet_gateway.cpp'), '-o', str(executable), *libraries], check=True)
    provider = 'vpn-tls.dll' if os.name == 'nt' else 'libvpn-tls.so'
    shutil.copy2(build / provider, destination / provider)
    return executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=pathlib.Path, required=True)
    parser.add_argument('--stable-build', type=pathlib.Path, required=True)
    parser.add_argument('--nodes', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--compiler', default='g++')
    parser.add_argument('--limit', type=int, default=8)
    parser.add_argument('--legacy-dns', action='store_true')
    parser.add_argument('--download', action='store_true')
    parser.add_argument('--qualified-only', action='store_true')
    args = parser.parse_args()
    args.build, args.stable_build, args.output = args.build.resolve(), args.stable_build.resolve(), args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    gateway = compile_gateway(args.build, args.output/'gateway', args.compiler)
    text = args.nodes.read_text(encoding='utf-8-sig')
    nodes = json.loads(text) if text.lstrip().startswith('[') else [{'Uri': uri} for uri in text.splitlines() if '://' in uri]
    records = []
    destination = socket.getaddrinfo('example.com', 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    for item in nodes[:args.limit]:
        uri = item.get('Uri', item.get('uri', ''))
        if not uri: continue
        record = {'node_id': hashlib.sha256(uri.encode()).hexdigest()[:16], 'protocol': uri.split('://', 1)[0]}
        with tempfile.TemporaryDirectory(prefix='vpn-native-internet-') as directory:
            config = pathlib.Path(directory)/'node.ini'
            with socket.socket() as selected: selected.bind(('127.0.0.1', 0)); port = selected.getsockname()[1]
            config.write_text('node_uri='+uri+'\nlisten_port='+str(port)+'\nconnect_timeout_ms=10000\nidle_timeout_ms=30000\nmax_connections=64\n', encoding='utf-8')
            stable = args.stable_build/('vpn-core.exe' if os.name == 'nt' else 'vpn-core')
            with process([str(stable), '--config', str(config)], args.stable_build) as (proc, events, condition):
                deadline = time.monotonic()+10
                while True:
                    try:
                        with socket.create_connection(('127.0.0.1', port), .2): break
                    except OSError:
                        if proc.poll() is not None or time.monotonic() > deadline: raise RuntimeError('Stable SOCKS did not start')
                        time.sleep(.05)
                record['stable_domain_https'] = observe(lambda: socks_request(port, 'example.com', 'example.com'))
                record['stable_ip_https'] = observe(lambda: socks_request(port, 'example.com', destination))
                record['stable_failures']=[{key:event.get(key) for key in ('phase','reason_code','native_status')} for event in events if event.get('event')=='failure']
                if args.qualified_only and record['stable_ip_https']['status']!='PASS':
                    records.append(record); print(json.dumps(record),flush=True); continue
                record['stable_direct_ip_https'] = observe(lambda: socks_request(port, 'one.one.one.one', '1.1.1.1', '/cdn-cgi/trace', b'ip='))
                if args.download:
                    record['stable_download']=observe(lambda:socks_request(port,'speed.cloudflare.com','speed.cloudflare.com','/__down?bytes=1048576',b''))
            cases=['native_ip_https','native_direct_ip_https','native_ipv4_dns','native_ipv6_dns','native_ipv4_tcp_dns']
            if args.download: cases.append('native_download')
            for name in cases:
                with process([str(gateway), '--config', str(config)], gateway.parent) as (proc, events, condition):
                    deadline = time.monotonic()+15
                    with condition:
                        while not any(event.get('event') == 'packet_gateway_ready' for event in events):
                            if proc.poll() is not None or time.monotonic() > deadline: raise RuntimeError('Packet gateway did not start')
                            condition.wait(.1)
                    packet_port = next(event['port'] for event in events if event.get('event') == 'packet_gateway_ready')
                    if name=='native_ipv4_tcp_dns':
                        record[name]=observe(lambda:tcp_dns_gateway(packet_port,'9.9.9.9' if args.legacy_dns else '198.18.0.53'))
                    elif name.endswith('dns'):
                        record[name] = observe(lambda: udp_dns(packet_port, ('9.9.9.9' if name == 'native_ipv4_dns' else '2620:fe::fe') if args.legacy_dns else ('198.18.0.53' if name == 'native_ipv4_dns' else 'fd71:5650::53')))
                    else:
                        def https():
                            app = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); app.connect(('127.0.0.1', packet_port))
                            client = None
                            try:
                                target=destination if name=='native_ip_https' else socket.getaddrinfo('speed.cloudflare.com',443,socket.AF_INET,socket.SOCK_STREAM)[0][4][0] if name=='native_download' else '1.1.1.1'
                                client = InternetTCPClient(app,target)
                                client.settimeout(15)
                                hostname='example.com' if name=='native_ip_https' else 'speed.cloudflare.com' if name=='native_download' else 'one.one.one.one'
                                stream = TLSStream(client,hostname)
                                result=request(stream,hostname,'/' if name=='native_ip_https' else '/__down?bytes=1048576' if name=='native_download' else '/cdn-cgi/trace',b'Example Domain' if name=='native_ip_https' else b'' if name=='native_download' else b'ip=')
                                if name=='native_download' and result['body_bytes']!=1048576:raise ValueError('Download length mismatch')
                                return result
                            finally:
                                if client: client.close()
                                app.send(b'STOP'); app.close()
                        record[name] = observe(https)
                    record[name]['flow_events'] = [event for event in events if event.get('event') in ('flow_failure', 'gateway_failure')]
            records.append(record)
            print(json.dumps(record), flush=True)
    report = {'schema': 'vpn-native-internet-v1', 'scope': 'Real verified HTTPS bodies and UDP DNS over IP packets; OS TUN/routing/policy NOT_TESTED',
              'provider_sha256': hashlib.sha256((args.build/('vpn-tls.dll' if os.name == 'nt' else 'libvpn-tls.so')).read_bytes()).hexdigest(),
              'bridge_sha256': hashlib.sha256((ROOT/'src/netstack-core.hpp').read_bytes()).hexdigest(), 'nodes': records}
    (args.output/'report.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')

if __name__ == '__main__': main()
