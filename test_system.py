"""Real TLS integration tests. Creates isolated keys and files in a temp dir."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import time
import unittest

from client import Client, Paused
from protocol import CHUNK, HEADER, MAGIC, MAX_META, Op, RemoteError, hash_file, keep_alive, receive_frame, send_frame
from server import Server
from setup_demo import initialize


class SystemTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='sft1-integration-')
        cls.runtime = Path(cls.temp.name) / 'runtime'
        initialize(cls.runtime, 0)
        cls.start_server()
        cls.results = {}

    @classmethod
    def start_server(cls):
        cls.server = Server(cls.runtime / 'server' / 'config.json')
        cls.thread = threading.Thread(target=cls.server.serve, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.close()
        cls.thread.join(2)
        print('\nMeasured results ' + json.dumps(cls.results, ensure_ascii=False))
        cls.temp.cleanup()

    def connection(self, user='alice'):
        return Client(self.runtime / 'clients' / user / 'profile.json', port=self.server.port)

    def local(self, name, data):
        path = self.runtime / name
        path.write_bytes(data)
        return path

    def wait_connections(self):
        deadline = time.monotonic() + 2
        while self.server.sockets and time.monotonic() < deadline:
            time.sleep(.01)

    def test_01_complete_empty_unicode_and_persistent(self):
        with self.connection() as client:
            session = client.info['session']
            for name, data in [('empty.bin', b''), ('中文文件.txt', '字节完整性\n'.encode()), ('binary.bin', bytes(range(256)) * 257)]:
                source = self.local(name, data)
                client.upload(source)
                target = self.runtime / 'downloads' / name
                client.download(name, target)
                self.assertEqual(target.read_bytes(), data)
            self.assertEqual(client.request(Op.PING)[0]['session'], session)
            self.results['tls'] = client.info['tls']
            self.results['round_trip_files'] = 3

    def test_02_resume_upload_and_download(self):
        data = bytes(range(256)) * 8192
        source = self.local('resume.bin', data)
        stop = threading.Event()
        def pause(done, total):
            if done >= 4 * CHUNK:
                stop.set()
        with self.connection() as client:
            with self.assertRaises(Paused):
                client.upload(source, cancel=stop, progress=pause)
        # The server process restarts while the partial upload stays on disk.
        self.server.close()
        self.thread.join(2)
        type(self).start_server()
        with self.connection() as client:
            result = client.upload(source)
            self.assertEqual(result['resumed'], 4 * CHUNK)
            self.results['upload_resume_bytes'] = result['resumed']
            target = self.runtime / 'downloads' / 'resume.bin'
            stop.clear()
            with self.assertRaises(Paused):
                client.download('resume.bin', target, cancel=stop, progress=pause)
            self.assertFalse(target.exists())
            result = client.download('resume.bin', target)
            self.assertEqual(result['resumed'], 4 * CHUNK)
            self.assertEqual(target.read_bytes(), data)
            self.results['download_resume_bytes'] = result['resumed']

    def test_03_user_isolation_and_paths(self):
        with self.connection('bob') as bob:
            self.assertEqual(bob.list_files(), [])
            with self.assertRaises(RemoteError) as caught:
                bob.download('resume.bin', self.runtime / 'forbidden.bin')
            self.assertEqual(caught.exception.code, 'NOT_FOUND')
            bad = ['../secret', '/etc/passwd', 'C:\\secret', 'x:stream', 'CON.txt', '..', 'a/b', "x'; DROP TABLE users;--"]
            for name in bad:
                with self.assertRaises(RemoteError):
                    bob.request(Op.PUT_BEGIN, {'name': name, 'size': 0, 'sha256': hashlib.sha256(b'').hexdigest()})
            self.assertEqual(bob.request(Op.HELLO, {'username': 'alice'})[0]['user'], 'bob')
            self.results['rejected_names'] = len(bad)

    def test_04_atomic_replace_and_conflict(self):
        source = self.local('atomic.bin', b'old version')
        with self.connection() as first, self.connection() as second:
            first.upload(source)
            first.request(Op.PUT_BEGIN, {'name': 'atomic.bin', 'size': 3, 'sha256': hashlib.sha256(b'abc').hexdigest()})
            with self.assertRaises(RemoteError) as caught:
                second.request(Op.PUT_BEGIN, {'name': 'atomic.bin', 'size': 0, 'sha256': hashlib.sha256(b'').hexdigest()})
            self.assertEqual(caught.exception.code, 'BUSY')
            first.request(Op.PUT_CHUNK, {'offset': 0}, b'xyz')
            with self.assertRaises(RemoteError) as caught:
                first.request(Op.PUT_FINISH)
            self.assertEqual(caught.exception.code, 'HASH')
            self.assertEqual((self.runtime / 'server/storage/alice/files/atomic.bin').read_bytes(), b'old version')

    def raw_tls(self, client_certificate=True, trust=True, hostname='localhost'):
        directory = self.runtime / 'clients/alice'
        context = ssl.create_default_context(cafile=directory / 'ca.pem' if trust else None)
        context.set_alpn_protocols(['sft/1'])
        if client_certificate:
            context.load_cert_chain(directory / 'identity.pem', directory / 'identity.key')
        raw = socket.create_connection(('127.0.0.1', self.server.port), timeout=3)
        try:
            secure = context.wrap_socket(raw, server_hostname=hostname)
            secure.settimeout(3)
            return secure
        except BaseException:
            raw.close()
            raise

    def test_05_authentication_and_mitm(self):
        for trust, hostname in [(False, 'localhost'), (True, 'wrong-host.invalid')]:
            with self.assertRaises(ssl.SSLCertVerificationError):
                self.raw_tls(trust=trust, hostname=hostname)
        with self.assertRaises((ssl.SSLError, EOFError, ConnectionError)):
            with self.raw_tls(client_certificate=False) as sock:
                send_frame(sock, Op.HELLO, 1)
                receive_frame(sock)
        self.results['tls_rejections'] = ['untrusted CA', 'wrong hostname', 'missing client certificate']

    def test_06_frame_fragmentation_and_limits(self):
        with self.raw_tls() as sock:
            data = HEADER.pack(MAGIC, 1, Op.PING, 0, 1, 2, 0) + b'{}'
            for byte in data:
                sock.sendall(bytes([byte]))
            self.assertEqual(receive_frame(sock)[2], 1)
            sock.sendall(HEADER.pack(MAGIC, 1, Op.PING, 0, 2, MAX_META + 1, 0))
            with self.assertRaises((OSError, EOFError)):
                receive_frame(sock)
        with self.raw_tls() as sock:
            frame = lambda n: HEADER.pack(MAGIC, 1, Op.PING, 0, n, 2, 0) + b'{}'
            sock.sendall(frame(1) + frame(2))
            self.assertEqual(receive_frame(sock)[2], 1)
            self.assertEqual(receive_frame(sock)[2], 2)
        with self.connection() as client:
            with self.assertRaises(RemoteError):
                client.request(Op.PUT_BEGIN, {'name': 'huge.bin', 'size': 2**40, 'sha256': hashlib.sha256(b'').hexdigest()})

    def test_07_parallel_transfers_and_shared_bandwidth(self):
        sources = [self.local(name, bytes([i]) * (512 * 1024))
                   for i, name in enumerate(('parallel-a.bin', 'parallel-b.bin', 'parallel-c.bin'))]
        def transfer(user, path):
            with self.connection(user) as client:
                start = time.monotonic()
                client.upload(path)
                return time.monotonic() - start
        with ThreadPoolExecutor(max_workers=3) as pool:
            started = time.monotonic()
            futures = [pool.submit(transfer, user, path) for user, path in zip(('alice', 'alice', 'bob'), sources)]
            times = [future.result() for future in futures]
            total = time.monotonic() - started
        self.assertGreaterEqual(times[2], 1.9)
        self.assertGreaterEqual(max(times[:2]), .9)
        self.results['concurrent_upload_seconds'] = [round(value, 3) for value in times]
        self.results['concurrent_wall_seconds'] = round(total, 3)
        with self.connection() as first, self.connection() as second:
            with ThreadPoolExecutor(max_workers=2) as pool:
                operations = [pool.submit(first.upload, sources[0], 'duplex-up.bin'),
                              pool.submit(second.download, 'parallel-b.bin', self.runtime / 'duplex-down.bin')]
                for future in operations:
                    future.result()
            self.assertEqual(hash_file(self.runtime / 'duplex-down.bin'), hash_file(sources[1]))

    def test_08_user_connection_cap(self):
        self.wait_connections()
        clients = []
        try:
            for _ in range(4):
                clients.append(self.connection())
            with self.assertRaises((OSError, EOFError)):
                self.connection()
            self.assertEqual(clients[0].request(Op.PING)[0]['session'], clients[0].info['session'])
        finally:
            for client in clients:
                client.close()

    def test_09_connection_survives_idle(self):
        with self.connection() as client:
            session = client.info['session']
            time.sleep(17)
            self.assertEqual(client.request(Op.PING)[0]['session'], session)
            self.assertGreater(client.request_id, 3)
            self.results['idle_seconds'] = 17

    def test_10_handshake_timeout_and_global_cap(self):
        config_path = self.runtime / 'server' / 'bounded-test.json'
        config = json.loads((self.runtime / 'server/config.json').read_text('utf-8'))
        config.update(max_connections=2, per_ip=2)
        config_path.write_text(json.dumps(config), encoding='utf-8')
        server = Server(config_path)
        thread = threading.Thread(target=server.serve, daemon=True)
        thread.start()
        sockets = []
        try:
            for _ in range(2):
                sockets.append(socket.create_connection(('127.0.0.1', server.port), timeout=3))
            deadline = time.monotonic() + 2
            while len(server.sockets) < 2 and time.monotonic() < deadline:
                time.sleep(.01)
            with socket.create_connection(('127.0.0.1', server.port), timeout=3) as extra:
                self.assertEqual(extra.recv(1), b'')
            start = time.monotonic()
            sockets[0].settimeout(6)
            self.assertEqual(sockets[0].recv(1), b'')
            self.results['handshake_timeout_seconds'] = round(time.monotonic() - start, 2)
        finally:
            for sock in sockets:
                sock.close()
            server.close()
            thread.join(2)

    def test_11_concurrent_small_file_finalization(self):
        source = self.local('small.txt', b'concurrent metadata publication\n')
        barrier = threading.Barrier(2)
        def upload_series(client, prefix):
            for number in range(10):
                barrier.wait(timeout=5)
                client.upload(source, f'{prefix}-{number}.txt')
        with self.connection() as first, self.connection() as second:
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(upload_series, first, 'small-a'),
                           pool.submit(upload_series, second, 'small-b')]
                for future in futures:
                    future.result()
            names = {item['name'] for item in first.list_files()}
            self.assertTrue(all(f'small-{prefix}-{n}.txt' in names for prefix in ('a', 'b') for n in range(10)))
            self.results['concurrent_small_files'] = 20


if __name__ == '__main__':
    unittest.main(verbosity=2)
