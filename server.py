"""Bounded concurrent mutual-TLS file server with isolated user storage."""

import argparse
from collections import Counter, deque
import hashlib
import json
import logging
import os
from pathlib import Path
import socket
import ssl
import stat
import threading
import time

from protocol import (CHUNK, ERROR, IO_TIMEOUT, MAX_FILE, RESPONSE, Op, ProtocolError,
                      digest, filename, hash_file, integer, keep_alive, receive_frame, send_frame)

LOG = logging.getLogger('sft.server')
QUOTA = 256 * 1024 * 1024
MAX_FILES = 256


class RequestError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def regular_path(path):
    """Reject symlinks and Windows reparse points, including junctions."""
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise RequestError('PATH', 'Links and reparse points are forbidden')
    return path


class Bandwidth:
    """Shared per-user scheduling for one direction, with no initial burst."""
    def __init__(self, rate):
        self.rate = integer(rate, CHUNK, 64 * 1024 * 1024)
        self.lock = threading.Lock()
        self.next_time = 0.0

    def consume(self, size):
        with self.lock:
            now = time.monotonic()
            self.next_time = max(now, self.next_time) + size / self.rate
            delay = self.next_time - now
        if delay:
            time.sleep(delay)


class Storage:
    def __init__(self, root, users):
        self.root = regular_path(root)
        self.root.mkdir(exist_ok=True)
        self.lock = threading.Lock()
        self.busy = set()
        for username in users:
            if not username.isascii() or not username.isalnum():
                raise ValueError('Configured usernames must be ASCII alphanumeric')
            directory = regular_path(self.root / username)
            directory.mkdir(exist_ok=True)
            for leaf in ('files', 'staging'):
                regular_path(directory / leaf).mkdir(exist_ok=True)

    def paths(self, user, name):
        name = filename(name)
        directory = regular_path(self.root / user)
        final = regular_path(regular_path(directory / 'files') / name)
        token = hashlib.sha256(name.casefold().encode()).hexdigest()
        staging = regular_path(directory / 'staging')
        part = regular_path(staging / (token + '.part'))
        meta = regular_path(staging / (token + '.json'))
        return final, part, meta

    def acquire(self, user, name):
        key = user, name.casefold()
        with self.lock:
            if key in self.busy:
                raise RequestError('BUSY', 'File is in use; retry after its transfer finishes')
            self.busy.add(key)
        return key

    def release(self, key):
        with self.lock:
            self.busy.discard(key)

    def prepare_upload(self, user, name, size, expected_hash, reset):
        final, part, meta = self.paths(user, name)
        expected = {'name': name, 'size': size, 'sha256': expected_hash}
        with self.lock:
            committed = list((self.root / user / 'files').iterdir())
            descriptors = list((self.root / user / 'staging').glob('*.json'))
            if not final.exists() and len(committed) + len(descriptors) >= MAX_FILES:
                raise RequestError('QUOTA', 'File count limit reached')
            reserved = sum(regular_path(p).stat().st_size for p in committed if p.is_file())
            for descriptor in descriptors:
                if descriptor != meta:
                    reserved += json.loads(regular_path(descriptor).read_text('utf-8'))['size']
            if reserved + size > QUOTA:
                raise RequestError('QUOTA', 'User storage quota reached')
            previous = json.loads(meta.read_text('utf-8')) if meta.exists() else None
            if reset or previous != expected or not part.exists() or part.stat().st_size > size:
                part.write_bytes(b'')
                temp = meta.with_suffix('.tmp')
                regular_path(temp).write_text(json.dumps(expected, ensure_ascii=False), encoding='utf-8')
                os.replace(temp, meta)
        return final, part, meta

    def listing(self, user, offset):
        directory = regular_path(regular_path(self.root / user) / 'files')
        items = []
        for path in sorted(directory.iterdir(), key=lambda p: p.name.casefold()):
            regular_path(path)
            if path.is_file():
                info = path.stat()
                items.append({'name': path.name, 'size': info.st_size, 'mtime': int(info.st_mtime)})
        return {'files': items[offset:offset + 32], 'next': offset + 32 if offset + 32 < len(items) else None}


class Session:
    def __init__(self, server, sock, user):
        self.server, self.sock, self.user = server, sock, user
        self.lock_key = None
        self.stream = None
        self.mode = None
        self.request_id = 0
        self.request_times = deque()
        self.offset = 0
        self.size = 0
        self.sha256 = ''
        self.paths = None
        self.session_id = os.urandom(8).hex()

    def release(self):
        if self.stream:
            self.stream.close()
        self.stream = None
        if self.lock_key:
            self.server.storage.release(self.lock_key)
        self.lock_key = None
        self.mode = None

    def run(self):
        try:
            while not self.server.stop_event.is_set():
                op, flags, request_id, meta, payload = receive_frame(self.sock)
                if flags or request_id <= self.request_id:
                    raise ProtocolError('Request IDs must increase')
                self.request_id = request_id
                now = time.monotonic()
                while self.request_times and now - self.request_times[0] > 1:
                    self.request_times.popleft()
                if len(self.request_times) >= 150:
                    raise ProtocolError('Request rate exceeded')
                self.request_times.append(now)
                try:
                    if payload and op != Op.PUT_CHUNK:
                        raise ProtocolError('Unexpected payload')
                    result, block = self.dispatch(op, meta, payload)
                    send_frame(self.sock, op, request_id, result, block, RESPONSE)
                except (RequestError, ProtocolError) as exc:
                    self.release()
                    send_frame(self.sock, op, request_id,
                               {'code': getattr(exc, 'code', 'BAD_REQUEST'), 'message': str(exc)}, flags=RESPONSE | ERROR)
                except OSError:
                    self.release()
                    send_frame(self.sock, op, request_id,
                               {'code': 'IO', 'message': 'Storage operation failed'}, flags=RESPONSE | ERROR)
                if op == Op.QUIT:
                    return
        finally:
            self.release()

    def dispatch(self, op, meta, payload):
        storage = self.server.storage
        if op == Op.HELLO:
            return {'user': self.user, 'session': self.session_id, 'chunk': CHUNK,
                    'max_file': MAX_FILE, 'rate': self.server.users[self.user]['bytes_per_second'],
                    'tls': self.sock.version()}, b''
        if op == Op.PING:
            return {'session': self.session_id}, b''
        if op == Op.QUIT or op == Op.RELEASE:
            self.release()
            return {'released': True}, b''
        if op == Op.LIST:
            return storage.listing(self.user, integer(meta.get('offset', 0), 0, MAX_FILES)), b''
        if op in (Op.PUT_BEGIN, Op.GET_BEGIN):
            if self.mode:
                raise RequestError('STATE', 'Release the active transfer first')
            name = filename(meta.get('name'))
            self.lock_key = storage.acquire(self.user, name)
            if op == Op.PUT_BEGIN:
                self.size = integer(meta.get('size'))
                self.sha256 = digest(meta.get('sha256'))
                reset = meta.get('reset', False)
                if type(reset) is not bool:
                    raise ProtocolError('reset must be boolean')
                self.paths = storage.prepare_upload(self.user, name, self.size, self.sha256, reset)
                part = self.paths[1]
                self.offset = part.stat().st_size
                prefix = hash_file(part)
                self.stream = part.open('ab')
                self.mode = 'put'
                return {'offset': self.offset, 'prefix_sha256': prefix}, b''
            final, _, _ = storage.paths(self.user, name)
            if not final.is_file():
                raise RequestError('NOT_FOUND', 'File does not exist in your space')
            self.stream = final.open('rb')
            self.size = final.stat().st_size
            self.sha256 = hash_file(final)
            requested = integer(meta.get('offset', 0))
            prefix = digest(meta.get('prefix_sha256'))
            self.offset = requested if requested <= self.size and hash_file(final, requested) == prefix else 0
            self.stream.seek(self.offset)
            self.mode = 'get'
            return {'size': self.size, 'sha256': self.sha256, 'offset': self.offset}, b''
        if op == Op.PUT_CHUNK:
            if self.mode != 'put' or integer(meta.get('offset')) != self.offset:
                raise RequestError('OFFSET', 'Unexpected upload offset')
            if not payload or self.offset + len(payload) > self.size:
                raise ProtocolError('Invalid upload chunk length')
            self.server.bandwidth[self.user, 'up'].consume(len(payload))
            self.stream.write(payload)
            self.stream.flush()
            self.offset += len(payload)
            return {'offset': self.offset}, b''
        if op == Op.PUT_FINISH:
            if self.mode != 'put' or self.offset != self.size:
                raise RequestError('STATE', 'Upload is incomplete')
            self.stream.flush()
            os.fsync(self.stream.fileno())
            self.stream.close()
            self.stream = None
            final, part, meta_path = self.paths
            if hash_file(part) != self.sha256:
                raise RequestError('HASH', 'Uploaded content failed SHA-256 validation')
            # Coordinate final publication with quota scans that read the
            # staging descriptors. Windows rejects deleting an open descriptor.
            with storage.lock:
                os.replace(part, final)
                meta_path.unlink(missing_ok=True)
            result = {'size': self.size, 'sha256': self.sha256}
            self.release()
            LOG.info('UPLOAD user=%s bytes=%s', self.user, result['size'])
            return result, b''
        if op == Op.GET_CHUNK:
            if self.mode != 'get' or integer(meta.get('offset')) != self.offset:
                raise RequestError('OFFSET', 'Unexpected download offset')
            block = self.stream.read(min(CHUNK, self.size - self.offset))
            self.server.bandwidth[self.user, 'down'].consume(len(block))
            self.offset += len(block)
            return {'offset': self.offset, 'eof': self.offset == self.size}, block
        raise ProtocolError('Unsupported operation')


class Server:
    def __init__(self, config_path):
        config_path = Path(config_path).resolve()
        self.config = json.loads(config_path.read_text('utf-8'))
        self.users = self.config['users']
        self.fingerprints = {digest(info['fingerprint']): name for name, info in self.users.items()}
        if len(self.fingerprints) != len(self.users):
            raise ValueError('Duplicate user certificate')
        self.storage = Storage(config_path.parent / self.config['storage'], self.users)
        self.bandwidth = {(name, direction): Bandwidth(info['bytes_per_second'])
                          for name, info in self.users.items() for direction in ('up', 'down')}
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(config_path.parent / 'identity.pem', config_path.parent / 'identity.key')
        self.context.load_verify_locations(config_path.parent / 'ca.pem')
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.set_alpn_protocols(['sft/1'])
        self.stop_event = threading.Event()
        self.guard = threading.Lock()
        self.peers = Counter()
        self.active_users = Counter()
        self.sockets = set()
        self.threads = set()
        self.admissions = {}
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if os.name == 'nt':
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((self.config['host'], self.config['port']))
        self.listener.listen(16)
        self.listener.settimeout(0.25)
        self.port = self.listener.getsockname()[1]

    def admit(self, sock, ip):
        now = time.monotonic()
        with self.guard:
            self.admissions = {key: times for key, times in self.admissions.items() if times[-1] > now - 60}
            times = self.admissions.setdefault(ip, deque())
            while times and times[0] <= now - 60:
                times.popleft()
            if (len(self.sockets) >= self.config['max_connections'] or
                    self.peers[ip] >= self.config['per_ip'] or len(times) >= 30 or len(self.admissions) > 1024):
                if not times:
                    self.admissions.pop(ip, None)
                return False
            times.append(now)
            self.sockets.add(sock)
            self.peers[ip] += 1
            return True

    def handle(self, raw, ip):
        secure = None
        user = None
        try:
            keep_alive(raw)
            raw.settimeout(4)
            secure = self.context.wrap_socket(raw, server_side=True, do_handshake_on_connect=False)
            with self.guard:
                self.sockets.discard(raw)
                self.sockets.add(secure)
            secure.do_handshake()
            if secure.selected_alpn_protocol() != 'sft/1':
                raise ProtocolError('ALPN sft/1 required')
            fingerprint = hashlib.sha256(secure.getpeercert(binary_form=True)).hexdigest()
            candidate = self.fingerprints.get(fingerprint)
            with self.guard:
                if candidate is None or self.active_users[candidate] >= self.config['per_user']:
                    raise ProtocolError('Unknown certificate or too many user sessions')
                user = candidate
                self.active_users[user] += 1
            secure.settimeout(IO_TIMEOUT)
            LOG.info('CONNECT user=%s tls=%s', user, secure.version())
            Session(self, secure, user).run()
        except (OSError, EOFError, ProtocolError, ValueError) as exc:
            LOG.debug('Session ended: %s', type(exc).__name__)
        finally:
            (secure or raw).close()
            with self.guard:
                self.sockets.discard(secure or raw)
                self.sockets.discard(raw)
                self.peers[ip] -= 1
                if not self.peers[ip]:
                    del self.peers[ip]
                if user:
                    self.active_users[user] -= 1
                self.threads.discard(threading.current_thread())

    def serve(self):
        LOG.info('READY %s:%s', self.config['host'], self.port)
        while not self.stop_event.is_set():
            try:
                sock, address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self.admit(sock, address[0]):
                sock.close()
                continue
            worker = threading.Thread(target=self.handle, args=(sock, address[0]), daemon=True)
            with self.guard:
                self.threads.add(worker)
            worker.start()

    def close(self):
        self.stop_event.set()
        self.listener.close()
        with self.guard:
            sockets, threads = list(self.sockets), list(self.threads)
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        for worker in threads:
            worker.join(IO_TIMEOUT + 1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='runtime/server/config.json')
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
    server = Server(args.config)
    try:
        server.serve()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
