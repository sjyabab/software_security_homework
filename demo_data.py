"""Synthetic Ethernet traffic for an offline, repeatable lab demonstration."""

from ipaddress import ip_address
import struct


DEMO_LINKTYPE = 1  # DLT_EN10MB

CLIENT_MAC = bytes.fromhex("02 00 00 00 00 10")
SERVER_MAC = bytes.fromhex("02 00 00 00 00 20")
DNS_MAC = bytes.fromhex("02 00 00 00 00 53")
CLIENT_IP = ip_address("192.0.2.10").packed
SERVER_IP = ip_address("192.0.2.20").packed
DNS_IP = ip_address("192.0.2.53").packed
CLIENT_V6 = ip_address("2001:db8::10").packed
SERVER_V6 = ip_address("2001:db8::20").packed


def _checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(word for (word,) in struct.iter_unpack("!H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _insert_checksum(data, offset, checksum):
    return data[:offset] + struct.pack("!H", checksum) + data[offset + 2:]


def _transport_checksum(src, dst, protocol, data):
    if len(src) == 4:
        suffix = struct.pack("!BBH", 0, protocol, len(data))
    else:
        suffix = struct.pack("!I3xB", len(data), protocol)
    return _checksum(src + dst + suffix + data)


def _ethernet(src, dst, ether_type, payload, vlan=None):
    header = dst + src
    if vlan is not None:
        header += struct.pack("!HH", 0x8100, vlan)
    frame = header + struct.pack("!H", ether_type) + payload
    return frame.ljust(60, b"\x00")  # Ethernet minimum size without FCS.


def _arp(operation, sender_mac, sender_ip, target_mac, target_ip):
    header = struct.pack("!HHBBH", 1, 0x0800, 6, 4, operation)
    return header + sender_mac + sender_ip + target_mac + target_ip


def _ip(src, dst, protocol, payload, identification):
    if len(src) == 4:
        header = struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), identification,
            0x4000, 64, protocol, 0, src, dst,
        )
        return 0x0800, _insert_checksum(header, 10, _checksum(header)) + payload
    header = struct.pack("!IHBB16s16s", 6 << 28, len(payload), protocol, 64, src, dst)
    return 0x86DD, header + payload


def _udp(src, dst, sport, dport, payload):
    segment = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    checksum = _transport_checksum(src, dst, 17, segment) or 0xFFFF
    return _insert_checksum(segment, 6, checksum)


def _tcp(src, dst, sport, dport, seq, ack, flags, payload):
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0)
    segment = header + payload
    return _insert_checksum(segment, 16, _transport_checksum(src, dst, 6, segment))


def _echo(src, dst, echo_type, protocol):
    message = struct.pack("!BBHHH", echo_type, 0, 0, 0x1A, 1) + b"lab1a echo"
    if protocol == 58:
        checksum = _transport_checksum(src, dst, protocol, message)
    else:
        checksum = _checksum(message)
    return _insert_checksum(message, 2, checksum)


def demo_packets():
    """Return (epoch seconds, captured Ethernet frame, wire length) triples."""
    frames = []

    def add_ip(src_mac, dst_mac, src, dst, protocol, payload, vlan=None):
        ether_type, packet = _ip(src, dst, protocol, payload, len(frames) + 1)
        frames.append(_ethernet(src_mac, dst_mac, ether_type, packet, vlan))

    def add_tcp(from_client, seq, ack, flags, payload=b"", ipv6=False):
        macs = CLIENT_MAC, SERVER_MAC
        if ipv6:
            ips = CLIENT_V6, SERVER_V6
            ports = 49153, 9000
        else:
            ips = CLIENT_IP, SERVER_IP
            ports = 49152, 8080
        if not from_client:
            macs, ips, ports = macs[::-1], ips[::-1], ports[::-1]
        segment = _tcp(*ips, *ports, seq, ack, flags, payload)
        add_ip(*macs, *ips, 6, segment, vlan=42 if ipv6 else None)

    # Address resolution and DNS A query/response.
    request = _arp(1, CLIENT_MAC, CLIENT_IP, bytes(6), SERVER_IP)
    reply = _arp(2, SERVER_MAC, SERVER_IP, CLIENT_MAC, CLIENT_IP)
    frames.append(_ethernet(CLIENT_MAC, b"\xff" * 6, 0x0806, request))
    frames.append(_ethernet(SERVER_MAC, CLIENT_MAC, 0x0806, reply))
    question = b"\x05lab1a\x04test\x00" + struct.pack("!HH", 1, 1)
    query = struct.pack("!6H", 0x1A, 0x0100, 1, 0, 0, 0) + question
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + SERVER_IP
    response = struct.pack("!6H", 0x1A, 0x8180, 1, 1, 0, 0) + question + answer
    add_ip(CLIENT_MAC, DNS_MAC, CLIENT_IP, DNS_IP, 17, _udp(CLIENT_IP, DNS_IP, 53000, 53, query))
    add_ip(DNS_MAC, CLIENT_MAC, DNS_IP, CLIENT_IP, 17, _udp(DNS_IP, CLIENT_IP, 53, 53000, response))

    # One complete TCP connection with a small plaintext HTTP exchange.
    syn, ack, push, fin = 0x02, 0x10, 0x08, 0x01
    client_seq, server_seq = 1001, 5001
    add_tcp(True, client_seq - 1, 0, syn)
    add_tcp(False, server_seq - 1, client_seq, syn | ack)
    add_tcp(True, client_seq, server_seq, ack)
    http_request = b"GET /lab1a HTTP/1.1\r\nHost: lab1a.test\r\nConnection: close\r\n\r\n"
    body = b"Lab 1A demo.\n"
    http_response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
        + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii")
        + body
    )
    add_tcp(True, client_seq, server_seq, push | ack, http_request)
    client_seq += len(http_request)
    add_tcp(False, server_seq, client_seq, push | ack, http_response)
    server_seq += len(http_response)
    add_tcp(True, client_seq, server_seq, ack)
    add_tcp(False, server_seq, client_seq, fin | ack)
    add_tcp(True, client_seq, server_seq + 1, fin | ack)
    add_tcp(False, server_seq + 1, client_seq + 1, ack)

    add_ip(CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP, 1, _echo(CLIENT_IP, SERVER_IP, 8, 1))
    add_ip(SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, 1, _echo(SERVER_IP, CLIENT_IP, 0, 1))

    # An independent TCP flow and echo pair on VLAN 42, using IPv6.
    add_tcp(True, 2000, 0, syn, ipv6=True)
    add_tcp(False, 9000, 2001, syn | ack, ipv6=True)
    add_tcp(True, 2001, 9001, ack, ipv6=True)
    add_ip(CLIENT_MAC, SERVER_MAC, CLIENT_V6, SERVER_V6, 58, _echo(CLIENT_V6, SERVER_V6, 128, 58), vlan=42)
    add_ip(SERVER_MAC, CLIENT_MAC, SERVER_V6, CLIENT_V6, 58, _echo(SERVER_V6, CLIENT_V6, 129, 58), vlan=42)

    start = 1794276000  # 2026-11-10 02:00:00 UTC.
    return [(start + index / 8, frame, len(frame)) for index, frame in enumerate(frames)]
