"""Bounds-checked decoding for Ethernet and Npcap loopback captures."""

import ipaddress
import re
import struct
from dataclasses import dataclass, field


Endpoint = tuple[str, int]
FlowKey = tuple[int, Endpoint, Endpoint]
Layer = tuple[str, tuple[tuple[str, str], ...]]

_VLAN_TYPES = {0x8100, 0x88A8, 0x9100}
_EXTENSIONS = {
    0: "Hop-by-Hop Options",
    43: "Routing",
    44: "Fragment",
    51: "Authentication",
    60: "Destination Options",
}
_TCP_FLAGS = (
    (0x100, "NS"), (0x080, "CWR"), (0x040, "ECE"), (0x020, "URG"),
    (0x010, "ACK"), (0x008, "PSH"), (0x004, "RST"), (0x002, "SYN"),
    (0x001, "FIN"),
)
_HTTP_REQUEST = re.compile(
    rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+ [!-~]+ HTTP/1\.[01]"
)
_HTTP_RESPONSE = re.compile(rb"HTTP/1\.[01] [1-5][0-9]{2} [\t -~]*")
_ICMP4_TYPES = {
    0: "Echo reply", 3: "Destination unreachable", 5: "Redirect",
    8: "Echo request", 11: "Time exceeded", 12: "Parameter problem",
}
_ICMP6_TYPES = {
    1: "Destination unreachable", 2: "Packet too big", 3: "Time exceeded",
    4: "Parameter problem", 128: "Echo request", 129: "Echo reply",
    133: "Router solicitation", 134: "Router advertisement",
    135: "Neighbor solicitation", 136: "Neighbor advertisement", 137: "Redirect",
}


@dataclass(frozen=True)
class DecodedPacket:
    source: str
    destination: str
    source_port: int | None
    destination_port: int | None
    protocol: str
    protocols: frozenset[str]
    summary: str
    layers: tuple[Layer, ...]
    flow_key: FlowKey | None
    warning: str


class _DecodeError(ValueError):
    pass


def _require(data: bytes, size: int, context: str) -> None:
    if len(data) < size:
        raise _DecodeError(f"{context} is truncated ({len(data)}/{size} bytes)")


def _mac(raw: bytes) -> str:
    return raw.hex(":")


def _hex16(number: int) -> str:
    return f"0x{number:04x}"


@dataclass
class _Decoder:
    source: str = ""
    destination: str = ""
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str = "UNKNOWN"
    protocols: set[str] = field(default_factory=set)
    summary: str = ""
    layers: list[Layer] = field(default_factory=list)
    flow_key: FlowKey | None = None
    warnings: list[str] = field(default_factory=list)

    def result(self) -> DecodedPacket:
        return DecodedPacket(
            self.source, self.destination, self.source_port, self.destination_port,
            self.protocol, frozenset(self.protocols), self.summary,
            tuple(self.layers), self.flow_key, " | ".join(self.warnings),
        )

    def mark(self, protocol: str) -> None:
        self.protocol = protocol
        self.protocols.add(protocol)

    def layer(self, name: str, fields: list[tuple[str, str | int]]) -> None:
        self.layers.append((name, tuple((label, str(value)) for label, value in fields)))

    def link(self, data: bytes, linktype: int) -> None:
        if linktype == 1:
            self.ethernet(data)
        elif linktype == 0:
            self.loopback(data)
        else:
            self.summary = f"Link type {linktype}"
            raise _DecodeError(f"Unsupported link type {linktype}")

    def ethernet(self, data: bytes) -> None:
        self.mark("ETHERNET")
        _require(data, 14, "Ethernet header")
        self.destination, self.source = _mac(data[:6]), _mac(data[6:12])
        kind = struct.unpack_from("!H", data, 12)[0]
        self.layer("Ethernet II", [
            ("Destination MAC", self.destination), ("Source MAC", self.source),
            ("EtherType", _hex16(kind)),
        ])
        data = data[14:]
        for _ in range(8):
            if kind not in _VLAN_TYPES:
                break
            _require(data, 4, "VLAN tag")
            tci, inner_type = struct.unpack_from("!HH", data)
            self.mark("VLAN")
            self.layer("802.1Q VLAN", [
                ("TPID", _hex16(kind)), ("VLAN ID", tci & 0xFFF),
                ("Priority", tci >> 13), ("Drop eligible", (tci >> 12) & 1),
                ("Encapsulated EtherType", _hex16(inner_type)),
            ])
            data, kind = data[4:], inner_type
        if kind in _VLAN_TYPES:
            raise _DecodeError("More than eight VLAN tags")
        if kind == 0x0800:
            self.ipv4(data)
        elif kind == 0x86DD:
            self.ipv6(data)
        elif kind == 0x0806:
            self.arp(data)
        else:
            self.summary = f"EtherType {_hex16(kind)}" if kind > 1500 else f"802.3 length {kind}"

    def loopback(self, data: bytes) -> None:
        self.mark("LOOPBACK")
        _require(data, 4, "Npcap loopback header")
        family = struct.unpack_from("<I", data)[0]
        self.layer("Npcap loopback", [("Address family", family)])
        if family == 2:
            self.ipv4(data[4:])
        elif family == 24:
            self.ipv6(data[4:])
        else:
            raise _DecodeError(f"Unsupported Npcap loopback address family {family}")

    def arp(self, data: bytes) -> None:
        self.mark("ARP")
        _require(data, 8, "ARP header")
        hardware, proto, hardware_len, proto_len, operation = struct.unpack_from("!HHBBH", data)
        _require(data, 8 + 2 * (hardware_len + proto_len), "ARP addresses")
        self.summary = {1: "ARP request", 2: "ARP reply"}.get(operation, f"ARP operation {operation}")
        fields = [
            ("Hardware type", hardware), ("Protocol type", _hex16(proto)),
            ("Hardware address length", hardware_len), ("Protocol address length", proto_len),
            ("Operation", operation),
        ]
        if hardware == 1 and proto == 0x0800 and (hardware_len, proto_len) == (6, 4):
            self.source = str(ipaddress.IPv4Address(data[14:18]))
            self.destination = str(ipaddress.IPv4Address(data[24:28]))
            fields.extend([
                ("Sender MAC", _mac(data[8:14])), ("Sender IP", self.source),
                ("Target MAC", _mac(data[18:24])), ("Target IP", self.destination),
            ])
            if operation == 1:
                self.summary = f"Who has {self.destination}? Tell {self.source}"
            elif operation == 2:
                self.summary = f"{self.source} is at {_mac(data[8:14])}"
        self.layer("ARP", fields)

    def ipv4(self, data: bytes) -> None:
        self.mark("IPV4")
        _require(data, 20, "IPv4 header")
        if data[0] >> 4 != 4:
            raise _DecodeError("Invalid IPv4 version")
        ihl = (data[0] & 0xF) * 4
        total, identification, flags_offset, ttl, protocol, checksum = struct.unpack_from("!HHHBBH", data, 2)
        if ihl < 20 or total < ihl:
            raise _DecodeError("Invalid IPv4 header or total length")
        _require(data, ihl, "IPv4 header with options")
        self.source = str(ipaddress.IPv4Address(data[12:16]))
        self.destination = str(ipaddress.IPv4Address(data[16:20]))
        offset = (flags_offset & 0x1FFF) * 8
        more_fragments = bool(flags_offset & 0x2000)
        self.layer("IPv4", [
            ("Source", self.source), ("Destination", self.destination),
            ("Header length", ihl), ("Total length", total), ("Identification", _hex16(identification)),
            ("Don't fragment", int(bool(flags_offset & 0x4000))),
            ("More fragments", int(more_fragments)), ("Fragment offset (bytes)", offset),
            ("TTL", ttl), ("Protocol", protocol), ("Header checksum", _hex16(checksum)),
        ])
        if total > len(data):
            self.warnings.append(f"IPv4 packet truncated ({len(data)}/{total} bytes)")
        if offset:
            self.summary = f"IPv4 non-initial fragment (offset {offset})"
            return
        self.transport(data[ihl:total], 4, protocol, more_fragments)

    def ipv6(self, data: bytes) -> None:
        self.mark("IPV6")
        _require(data, 40, "IPv6 header")
        first_word, payload_length, protocol, hop_limit = struct.unpack_from("!IHBB", data)
        if first_word >> 28 != 6:
            raise _DecodeError("Invalid IPv6 version")
        self.source = str(ipaddress.IPv6Address(data[8:24]))
        self.destination = str(ipaddress.IPv6Address(data[24:40]))
        self.layer("IPv6", [
            ("Source", self.source), ("Destination", self.destination),
            ("Traffic class", (first_word >> 20) & 0xFF),
            ("Flow label", f"0x{first_word & 0xFFFFF:05x}"), ("Payload length", payload_length),
            ("Next header", protocol), ("Hop limit", hop_limit),
        ])
        if not payload_length and protocol == 0:
            raise _DecodeError("IPv6 jumbograms are unsupported")
        available = len(data) - 40
        if payload_length > available:
            self.warnings.append(f"IPv6 payload truncated ({available}/{payload_length} bytes)")
        data = data[40:40 + payload_length]
        more_fragments = False
        for _ in range(16):
            if protocol not in _EXTENSIONS:
                break
            next_header, length, offset, fragment_flag = self.ipv6_extension(data, protocol)
            data, protocol = data[length:], next_header
            more_fragments |= fragment_flag
            if offset:
                self.summary = f"IPv6 non-initial fragment (offset {offset})"
                return
        if protocol in _EXTENSIONS:
            raise _DecodeError("More than sixteen IPv6 extension headers")
        self.transport(data, 6, protocol, more_fragments)

    def ipv6_extension(self, data: bytes, protocol: int) -> tuple[int, int, int, bool]:
        label = _EXTENSIONS[protocol]
        context = f"IPv6 {label} header"
        _require(data, 2, context)
        next_header, size_field = data[:2]
        offset = 0
        more_fragments = False
        if protocol == 44:
            length = 8
        elif protocol == 51:
            length = (size_field + 2) * 4
            if length < 12:
                raise _DecodeError("Invalid IPv6 Authentication header length")
        else:
            length = (size_field + 1) * 8
        _require(data, length, context)
        fields = [("Length", length), ("Next header", next_header)]
        if protocol == 44:
            fragment, identification = struct.unpack_from("!HI", data, 2)
            offset = fragment & 0xFFF8
            more_fragments = bool(fragment & 1)
            fields.extend([
                ("Identification", f"0x{identification:08x}"),
                ("Fragment offset (bytes)", offset), ("More fragments", int(more_fragments)),
            ])
        self.layer(f"IPv6 {label}", fields)
        return next_header, length, offset, more_fragments

    def transport(self, data: bytes, version: int, protocol: int, fragmented: bool) -> None:
        if protocol == 6:
            self.tcp(data, version, fragmented)
        elif protocol == 17:
            self.udp(data, fragmented)
        elif (version, protocol) in ((4, 1), (6, 58)):
            self.icmp(data, version)
        elif version == 6 and protocol == 59:
            self.summary = "IPv6 No Next Header"
        else:
            self.summary = f"IPv{version} protocol {protocol}"

    def tcp(self, data: bytes, version: int, fragmented: bool) -> None:
        self.mark("TCP")
        _require(data, 20, "TCP header")
        source_port, destination_port, seq, ack, offset_flags, window, checksum, urgent = struct.unpack_from(
            "!HHIIHHHH", data
        )
        header_length = (offset_flags >> 12) * 4
        if header_length < 20:
            raise _DecodeError("Invalid TCP data offset")
        _require(data, header_length, "TCP header with options")
        self.source_port, self.destination_port = source_port, destination_port
        first, second = sorted(((self.source, source_port), (self.destination, destination_port)))
        self.flow_key = (version, first, second)
        flags = ", ".join(label for mask, label in _TCP_FLAGS if offset_flags & mask) or "None"
        payload = data[header_length:]
        self.summary = f"{source_port} -> {destination_port} [{flags}] Seq={seq} Ack={ack} Len={len(payload)}"
        self.layer("TCP", [
            ("Source port", source_port), ("Destination port", destination_port),
            ("Sequence number", seq), ("Acknowledgment number", ack),
            ("Header length", header_length), ("Flags", flags), ("Window", window),
            ("Checksum", _hex16(checksum)), ("Urgent pointer", urgent),
            ("Captured payload bytes", len(payload)),
        ])
        if not fragmented and payload:
            self.http(payload)

    def http(self, payload: bytes) -> None:
        line_end = payload.find(b"\r\n", 0, 4096)
        if line_end < 0:
            return
        line = payload[:line_end]
        if _HTTP_REQUEST.fullmatch(line):
            role = "Request"
        elif _HTTP_RESPONSE.fullmatch(line):
            role = "Response"
        else:
            return
        self.mark("HTTP")
        start_line = line.decode("ascii").replace("\t", " ")
        self.summary = start_line[:200] + ("..." if len(start_line) > 200 else "")
        self.layer("HTTP/1.x", [("Kind", role), ("Start line", start_line)])

    def udp(self, data: bytes, fragmented: bool) -> None:
        self.mark("UDP")
        _require(data, 8, "UDP header")
        source_port, destination_port, length, checksum = struct.unpack_from("!HHHH", data)
        if length < 8:
            raise _DecodeError("Invalid UDP length")
        self.source_port, self.destination_port = source_port, destination_port
        self.summary = f"{source_port} -> {destination_port} Len={length - 8}"
        self.layer("UDP", [
            ("Source port", source_port), ("Destination port", destination_port),
            ("Length", length), ("Checksum", _hex16(checksum)),
        ])
        if fragmented:
            return
        _require(data, length, "UDP datagram")
        if 53 in (source_port, destination_port):
            self.dns(data[8:length])

    def dns(self, data: bytes) -> None:
        _require(data, 12, "DNS header")
        ident, flags, questions, answers, authority, additional = struct.unpack_from("!6H", data)
        kind = "response" if flags & 0x8000 else "query"
        self.mark("DNS")
        self.summary = f"DNS {kind} {_hex16(ident)}"
        fields = [
            ("Transaction ID", _hex16(ident)), ("Flags", _hex16(flags)),
            ("Questions", questions), ("Answers", answers),
            ("Authority records", authority), ("Additional records", additional),
        ]
        if questions:
            try:
                name, question_end = _dns_name(data, 12)
                _require(data, question_end + 4, "DNS question type and class")
                qtype, qclass = struct.unpack_from("!HH", data, question_end)
                fields.extend([("First question", name), ("QTYPE", qtype), ("QCLASS", qclass)])
                self.summary += f" {name}"
            except _DecodeError as error:
                self.warnings.append(str(error))
        self.layer("DNS", fields)

    def icmp(self, data: bytes, version: int) -> None:
        self.mark("ICMP" if version == 4 else "ICMPV6")
        label = "ICMP" if version == 4 else "ICMPv6"
        types = _ICMP4_TYPES if version == 4 else _ICMP6_TYPES
        _require(data, 4, f"{label} header")
        message_type, code, checksum = struct.unpack_from("!BBH", data)
        description = types.get(message_type, f"Type {message_type}")
        self.summary = f"{description} (code {code})"
        fields = [("Type", f"{message_type} ({description})"), ("Code", code), ("Checksum", _hex16(checksum))]
        echo_types = (0, 8) if version == 4 else (128, 129)
        if message_type in echo_types and len(data) >= 8:
            ident, sequence = struct.unpack_from("!HH", data, 4)
            fields.extend([("Identifier", _hex16(ident)), ("Sequence", sequence)])
        elif message_type in echo_types:
            self.warnings.append(f"{label} echo header is truncated")
        self.layer(label, fields)


def _dns_name(data: bytes, start: int) -> tuple[str, int]:
    labels = []
    seen = set()
    position = start
    next_field = None
    wire_length = 1  # Root label terminator.
    while True:
        _require(data, position + 1, "DNS name")
        size = data[position]
        if size == 0:
            return ".".join(labels) or ".", next_field or position + 1
        if size & 0xC0 == 0xC0:
            _require(data, position + 2, "DNS compression pointer")
            if len(seen) == 32 or position in seen:
                raise _DecodeError("Invalid DNS compression pointer chain")
            seen.add(position)
            if next_field is None:
                next_field = position + 2
            position = ((size & 0x3F) << 8) | data[position + 1]
            continue
        wire_length += size + 1
        if size > 63 or wire_length > 255:
            raise _DecodeError("Invalid DNS label length")
        end = position + 1 + size
        _require(data, end, "DNS label")
        label = data[position + 1:end]
        labels.append("".join(chr(byte) if 33 <= byte <= 126 and byte not in (46, 92) else f"\\x{byte:02x}" for byte in label))
        position = end


def decode_packet(data: bytes, linktype: int) -> DecodedPacket:
    """Decode a single captured frame, retaining partial details on malformed input."""
    decoder = _Decoder()
    try:
        decoder.link(data, linktype)
    except _DecodeError as error:
        decoder.warnings.append(str(error))
    if not decoder.summary:
        decoder.summary = decoder.warnings[-1] if decoder.warnings else decoder.protocol
    return decoder.result()
