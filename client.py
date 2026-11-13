"""Persistent authenticated client with verified resumable file transfers."""

import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import threading
import time

from protocol import (CHUNK, ERROR, IO_TIMEOUT, MAX_FILE, RESPONSE, Op, ProtocolError,
                      RemoteError, digest, filename, hash_file, integer, keep_alive, receive_frame, send_frame)


class Paused(Exception):
    pass


class Client:
    def __init__(self, profile_path, host=None, port=None):
        profile_path = Path(profile_path).resolve()
        profile = json.loads(profile_path.read_text('utf-8'))
        self.profile = profile
        self.lock = threading.RLock()
        self.closed = threading.Event()
        self.last_activity = time.monotonic()
        self.request_id = 0
        self.sock = None
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=profile_path.parent / profile['ca'])
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(profile_path.parent / profile['cert'], profile_path.parent / profile['key'])
        context.set_alpn_protocols(['sft/1'])
        hostname = host or profile['host']
        self.endpoint = (hostname, port if port is not None else profile['port'])
        raw = socket.create_connection(self.endpoint, timeout=4)
        try:
            keep_alive(raw)
            self.sock = context.wrap_socket(raw, server_hostname=hostname)
            if self.sock.selected_alpn_protocol() != 'sft/1':
                raise ProtocolError('Server does not support SFT1')
            self.sock.settimeout(IO_TIMEOUT)
            self.info, _ = self.request(Op.HELLO)
            if self.info['user'] != profile['username']:
                raise ProtocolError('Certificate identity differs from selected profile')
        except BaseException:
            (self.sock or raw).close()
            raise
        self.heartbeat = threading.Thread(target=self._heartbeat, daemon=True)
        self.heartbeat.start()

    def request(self, op, metadata=None, payload=b''):
        with self.lock:
            if self.closed.is_set():
                raise ConnectionError('Connection closed; reconnect to resume')
            self.request_id += 1
            try:
                send_frame(self.sock, op, self.request_id, metadata, payload)
                reply_op, flags, reply_id, meta, data = receive_frame(self.sock)
                if reply_op != op or reply_id != self.request_id or flags not in (RESPONSE, RESPONSE | ERROR):
                    raise ProtocolError('Unexpected response')
            except (OSError, EOFError, ProtocolError):
                self.closed.set()
                self.sock.close()
                raise
            self.last_activity = time.monotonic()
            if flags & ERROR:
                raise RemoteError(meta.get('code', 'ERROR'), meta.get('message', 'Server rejected request'))
            return meta, data

    def _heartbeat(self):
        while not self.closed.wait(5):
            try:
                with self.lock:
                    if time.monotonic() - self.last_activity >= 4:
                        self.request(Op.PING)
            except (OSError, EOFError, ProtocolError, RemoteError):
                self.closed.set()
                self.sock.close()
                return

    def list_files(self):
        with self.lock:
            result = []
            offset = 0
            while offset is not None:
                meta, _ = self.request(Op.LIST, {'offset': offset})
                result.extend(meta['files'])
                offset = meta['next']
            return result

    def _release(self):
        if not self.closed.is_set():
            try:
                self.request(Op.RELEASE)
            except (OSError, EOFError, ProtocolError, RemoteError):
                self.closed.set()
                self.sock.close()

    def upload(self, local_path, remote_name=None, cancel=None, progress=None):
        path = Path(local_path)
        name = filename(remote_name or path.name)
        size = path.stat().st_size
        if size > MAX_FILE:
            raise ValueError('单个文件上限为 64 MiB')
        checksum = hash_file(path)
        begin = {'name': name, 'size': size, 'sha256': checksum}
        with self.lock:
            try:
                meta, _ = self.request(Op.PUT_BEGIN, begin)
                offset = integer(meta['offset'], 0, size)
                if hash_file(path, offset) != meta['prefix_sha256']:
                    self._release()
                    meta, _ = self.request(Op.PUT_BEGIN, {**begin, 'reset': True})
                    offset = meta['offset']
                resumed = offset
                if progress:
                    progress(offset, size)
                with path.open('rb') as stream:
                    stream.seek(offset)
                    while offset < size:
                        if cancel is not None and cancel.is_set():
                            raise Paused('已暂停，保留服务器断点')
                        data = stream.read(min(CHUNK, size - offset))
                        if not data:
                            raise OSError('源文件在传输过程中变短')
                        meta, _ = self.request(Op.PUT_CHUNK, {'offset': offset}, data)
                        offset += len(data)
                        if meta.get('offset') != offset:
                            raise ProtocolError('Unexpected acknowledged offset')
                        if progress:
                            progress(offset, size)
                if cancel is not None and cancel.is_set():
                    raise Paused('已暂停，保留服务器断点')
                result, _ = self.request(Op.PUT_FINISH)
                if result.get('size') != size or result.get('sha256') != checksum:
                    raise ProtocolError('Invalid upload completion response')
                return {**result, 'resumed': resumed}
            finally:
                self._release()

    def download(self, remote_name, target, cancel=None, progress=None):
        name = filename(remote_name)
        target = Path(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        part = target.with_name(target.name + '.sft-part')
        marker = target.with_name(target.name + '.sft-meta')
        identity = {'name': name, 'user': self.info['user'],
                    'server': self.endpoint[0], 'port': self.endpoint[1]}
        previous = None
        if marker.exists():
            try:
                previous = json.loads(marker.read_text('utf-8'))
            except (ValueError, UnicodeError):
                pass
        offset = part.stat().st_size if previous and previous.get('identity') == identity and part.exists() else 0
        if offset > MAX_FILE:
            offset = 0
        prefix = hash_file(part, offset) if offset else hashlib.sha256(b'').hexdigest()
        with self.lock:
            try:
                meta, _ = self.request(Op.GET_BEGIN, {'name': name, 'offset': offset, 'prefix_sha256': prefix})
                size = integer(meta['size'])
                offset = integer(meta['offset'], 0, min(size, offset))
                checksum = digest(meta['sha256'])
                resumed = offset
                marker.write_text(json.dumps({'identity': identity, 'sha256': checksum}), encoding='utf-8')
                with part.open('r+b' if part.exists() else 'w+b') as stream:
                    stream.truncate(offset)
                    stream.seek(offset)
                    if progress:
                        progress(offset, size)
                    while offset < size:
                        if cancel is not None and cancel.is_set():
                            raise Paused('已暂停，保留本地断点')
                        reply, data = self.request(Op.GET_CHUNK, {'offset': offset})
                        if not data or offset + len(data) > size or reply.get('offset') != offset + len(data):
                            raise ProtocolError('Invalid download chunk')
                        stream.write(data)
                        stream.flush()
                        offset += len(data)
                        if progress:
                            progress(offset, size)
                    stream.flush()
                    os.fsync(stream.fileno())
                if hash_file(part) != checksum:
                    raise ProtocolError('Downloaded file failed SHA-256 validation')
                os.replace(part, target)
                marker.unlink(missing_ok=True)
                return {'size': size, 'sha256': checksum, 'resumed': resumed}
            finally:
                self._release()

    def close(self):
        with self.lock:
            if not self.closed.is_set():
                try:
                    self.request(Op.QUIT)
                except (OSError, EOFError, ProtocolError, RemoteError):
                    pass
                self.closed.set()
                self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
