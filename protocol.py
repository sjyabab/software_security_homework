"""SFT1 framing and validation shared by the TLS client and server."""

import hashlib
import json
import re
import socket
import struct
import time
import unicodedata
from enum import IntEnum

HEADER = struct.Struct('!4sBBHIII')
MAGIC = b'SFT1'
VERSION = 1
RESPONSE, ERROR = 1, 2
MAX_META = 16384
CHUNK = 65536
MAX_FILE = 64 * 1024 * 1024
IO_TIMEOUT = 15.0


class Op(IntEnum):
    HELLO = 1
    PING = 2
    LIST = 3
    PUT_BEGIN = 10
    PUT_CHUNK = 11
    PUT_FINISH = 12
    RELEASE = 13
    GET_BEGIN = 20
    GET_CHUNK = 21
    QUIT = 30


class ProtocolError(Exception):
    pass


class RemoteError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def receive_exact(sock, size, deadline):
    data = bytearray()
    while len(data) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Frame deadline exceeded')
        sock.settimeout(remaining)
        block = sock.recv(size - len(data))
        if not block:
            raise EOFError('Connection closed')
        data.extend(block)
    return bytes(data)


def receive_frame(sock):
    deadline = time.monotonic() + IO_TIMEOUT
    fields = HEADER.unpack(receive_exact(sock, HEADER.size, deadline))
    magic, version, opcode, flags, request_id, meta_size, data_size = fields
    if magic != MAGIC or version != VERSION or flags & ~3 or not request_id:
        raise ProtocolError('Invalid frame header')
    if meta_size > MAX_META or data_size > CHUNK:
        raise ProtocolError('Frame exceeds size limit')
    try:
        op = Op(opcode)
        metadata = json.loads(receive_exact(sock, meta_size, deadline).decode('utf-8'))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ProtocolError('Invalid opcode or JSON') from exc
    if not isinstance(metadata, dict):
        raise ProtocolError('JSON metadata must be an object')
    payload = receive_exact(sock, data_size, deadline)
    sock.settimeout(IO_TIMEOUT)
    return op, flags, request_id, metadata, payload


def send_frame(sock, op, request_id, metadata=None, payload=b'', flags=0):
    encoded = json.dumps(metadata or {}, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
    if len(encoded) > MAX_META or len(payload) > CHUNK:
        raise ProtocolError('Frame exceeds size limit')
    sock.settimeout(IO_TIMEOUT)
    sock.sendall(HEADER.pack(MAGIC, VERSION, op, flags, request_id, len(encoded), len(payload)) + encoded + payload)


def keep_alive(sock):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


def integer(value, minimum=0, maximum=MAX_FILE):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ProtocolError('Integer out of range')
    return value


def digest(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value):
        raise ProtocolError('Invalid SHA-256')
    return value


def filename(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 100:
        raise ProtocolError('Invalid filename length')
    if unicodedata.normalize('NFC', value) != value or not re.fullmatch(r'[\w ()+.-]+', value):
        raise ProtocolError('Unsupported filename characters')
    if value.startswith('.') or value.endswith(('.', ' ')):
        raise ProtocolError('Invalid filename')
    stem = value.split('.')[0].upper()
    if stem in {'CON', 'PRN', 'AUX', 'NUL', 'CLOCK$', 'CONIN$', 'CONOUT$'} or re.fullmatch(r'(COM|LPT)[0-9¹²³]', stem):
        raise ProtocolError('Reserved device name')
    return value


def hash_file(path, limit=None):
    result = hashlib.sha256()
    with open(path, 'rb') as stream:
        while limit is None or limit > 0:
            block = stream.read(CHUNK if limit is None else min(CHUNK, limit))
            if not block:
                break
            result.update(block)
            if limit is not None:
                limit -= len(block)
    return result.hexdigest()
