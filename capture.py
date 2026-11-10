"""Passive Npcap capture on Windows and portable classic PCAP file I/O."""

import ctypes as C
import math
import os
import struct
import tempfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


class CaptureError(RuntimeError):
    """A capture source or PCAP file cannot be used."""


@dataclass(frozen=True, slots=True)
class Interface:
    name: str
    description: str


@dataclass(frozen=True, slots=True)
class Frame:
    timestamp: float
    data: bytes
    original_length: int


_ERRBUF_SIZE = 256
_LIVE_SNAPLEN = 65535
_MAX_FILE_FRAME = 16 * 1024 * 1024
_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}


class _PcapInterface(C.Structure):
    pass


_InterfacePtr = C.POINTER(_PcapInterface)
_PcapInterface._fields_ = [
    ("next", _InterfacePtr),
    ("name", C.c_char_p),
    ("description", C.c_char_p),
    ("addresses", C.c_void_p),
    ("flags", C.c_uint32),
]


class _PacketHeader(C.Structure):
    # Windows timeval uses 32-bit long on both 32-bit and 64-bit builds.
    _fields_ = [
        ("seconds", C.c_int32),
        ("microseconds", C.c_int32),
        ("captured_length", C.c_uint32),
        ("original_length", C.c_uint32),
    ]


class _BpfProgram(C.Structure):
    _fields_ = [("length", C.c_uint), ("instructions", C.c_void_p)]


_HeaderPtr = C.POINTER(_PacketHeader)
_BpfPtr = C.POINTER(_BpfProgram)


@lru_cache(maxsize=1)
def _npcap():
    if os.name != "nt":
        raise CaptureError("实时抓包需要 Windows 和 Npcap，可改用离线 PCAP。")

    system = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    last_error = None
    # Prefer the current Npcap installation. The second location covers its
    # WinPcap compatibility mode. Never search the working directory for DLLs.
    for path in (system / "Npcap" / "wpcap.dll", system / "wpcap.dll"):
        try:
            lib = C.CDLL(str(path), winmode=0x00000100 | 0x00000800)
            lib.pcap_lib_version.argtypes = []
            lib.pcap_lib_version.restype = C.c_char_p
            if b"npcap" in lib.pcap_lib_version().lower():
                break
        except (OSError, AttributeError) as error:
            last_error = error
    else:
        raise CaptureError("未找到可用的 Npcap。请安装 Npcap，或打开离线 PCAP。") from last_error

    signatures = {
        "pcap_init": (C.c_int, C.c_uint, C.c_char_p),
        "pcap_findalldevs": (C.c_int, C.POINTER(_InterfacePtr), C.c_char_p),
        "pcap_freealldevs": (None, _InterfacePtr),
        "pcap_open_live": (C.c_void_p, C.c_char_p, C.c_int, C.c_int, C.c_int, C.c_char_p),
        "pcap_datalink": (C.c_int, C.c_void_p),
        "pcap_compile": (C.c_int, C.c_void_p, _BpfPtr, C.c_char_p, C.c_int, C.c_uint32),
        "pcap_setfilter": (C.c_int, C.c_void_p, _BpfPtr),
        "pcap_freecode": (None, _BpfPtr),
        "pcap_setmintocopy": (C.c_int, C.c_void_p, C.c_int),
        "pcap_setnonblock": (C.c_int, C.c_void_p, C.c_int, C.c_char_p),
        "pcap_next_ex": (C.c_int, C.c_void_p, C.POINTER(_HeaderPtr), C.POINTER(C.c_void_p)),
        "pcap_geterr": (C.c_char_p, C.c_void_p),
        "pcap_close": (None, C.c_void_p),
    }
    try:
        for name, (restype, *argtypes) in signatures.items():
            function = getattr(lib, name)
            function.argtypes = argtypes
            function.restype = restype
    except AttributeError as error:
        raise CaptureError("Npcap 缺少所需接口，请更新 Npcap。") from error

    errbuf = C.create_string_buffer(_ERRBUF_SIZE)
    if lib.pcap_init(1, errbuf) != 0:  # PCAP_CHAR_ENC_UTF_8
        raise CaptureError(f"Npcap 初始化失败：{_pcap_text(errbuf.value)}")
    return lib


def _pcap_text(value):
    return value.decode("utf-8", errors="replace") if value else "无详细错误信息"


def list_interfaces() -> list[Interface]:
    lib = _npcap()
    errbuf = C.create_string_buffer(_ERRBUF_SIZE)
    head = _InterfacePtr()
    if lib.pcap_findalldevs(C.byref(head), errbuf) != 0:
        raise CaptureError(f"无法枚举抓包网卡：{_pcap_text(errbuf.value)}")

    interfaces = []
    try:
        item = head
        while item:
            entry = item.contents
            name = _pcap_text(entry.name)
            description = _pcap_text(entry.description) if entry.description else name
            interfaces.append(Interface(name, description))
            item = entry.next
    finally:
        if head:
            lib.pcap_freealldevs(head)
    return interfaces


class LiveCapture:
    """Use a handle on one worker thread and close it via the context manager."""

    def __init__(self, interface_name: str, bpf: str = ""):
        self._interface_name = interface_name
        self._bpf = bpf.strip()
        self._handle = None
        self.linktype = None

    def __enter__(self):
        if self._handle is not None:
            raise CaptureError("该采集句柄已打开。")
        if not self._interface_name or "\0" in self._interface_name or "\0" in self._bpf:
            raise CaptureError("网卡名称或 BPF 表达式无效。")

        self._lib = _npcap()
        errbuf = C.create_string_buffer(_ERRBUF_SIZE)
        self._handle = self._lib.pcap_open_live(
            self._interface_name.encode("utf-8"), _LIVE_SNAPLEN, 0, 50, errbuf
        )
        if not self._handle:
            self._handle = None
            raise CaptureError(f"无法打开网卡：{_pcap_text(errbuf.value)}")

        try:
            linktype = self._lib.pcap_datalink(self._handle)
            if linktype < 0:
                raise self._error("无法识别网卡链路类型")
            # Windows DLT_RAW is 12, whereas PCAP LINKTYPE_RAW is 101.
            self.linktype = 101 if linktype == 12 else linktype
            if self._bpf:
                self._apply_bpf()
            if self._lib.pcap_setmintocopy(self._handle, 0) != 0:
                raise self._error("无法设置即时读包")
            if self._lib.pcap_setnonblock(self._handle, 1, errbuf) != 0:
                raise CaptureError(f"无法启用非阻塞抓包：{_pcap_text(errbuf.value)}")
        except BaseException:
            self.close()
            raise
        return self

    def _error(self, prefix):
        return CaptureError(f"{prefix}：{_pcap_text(self._lib.pcap_geterr(self._handle))}")

    def _apply_bpf(self):
        program = _BpfProgram()
        if self._lib.pcap_compile(
            self._handle, C.byref(program), self._bpf.encode("utf-8"), 1, 0xFFFFFFFF
        ) != 0:
            raise self._error("BPF 编译失败")
        try:
            if self._lib.pcap_setfilter(self._handle, C.byref(program)) != 0:
                raise self._error("无法应用 BPF 过滤器")
        finally:
            self._lib.pcap_freecode(C.byref(program))

    def read(self) -> Frame | None:
        if self._handle is None:
            raise CaptureError("请先打开采集句柄。")
        header = _HeaderPtr()
        packet = C.c_void_p()
        result = self._lib.pcap_next_ex(self._handle, C.byref(header), C.byref(packet))
        if result == 0:
            return None
        if result != 1:
            raise self._error("网卡读包失败")

        if not header:
            raise CaptureError("Npcap 返回了空包头。")
        info = header.contents
        if info.captured_length > min(info.original_length, _LIVE_SNAPLEN):
            raise CaptureError("Npcap 返回了无效的包长。")
        if info.captured_length and not packet:
            raise CaptureError("Npcap 返回了空数据指针。")
        return Frame(
            info.seconds + info.microseconds / 1_000_000,
            C.string_at(packet, info.captured_length) if info.captured_length else b"",
            info.original_length,
        )

    def close(self):
        if self._handle is not None:
            self._lib.pcap_close(self._handle)
            self._handle = None

    def __exit__(self, exc_type, exc, traceback):
        self.close()


class PcapReader:
    """Read classic PCAP 2.4 with either byte order and timestamp precision."""

    def __init__(self, path):
        self._path = Path(path)
        self._stream = None
        self.linktype = None

    def __enter__(self):
        if self._stream is not None:
            raise CaptureError("该 PCAP 文件已打开。")
        try:
            self._stream = self._path.open("rb")
            header = self._stream.read(24)
            if header[:4] == b"\x0a\x0d\x0d\x0a":
                raise CaptureError("这是 PCAPNG 文件，请转换为经典 PCAP 后打开。")
            if len(header) != 24 or header[:4] not in _PCAP_MAGICS:
                raise CaptureError("PCAP 全局头不完整或格式无法识别。")
            endian, self._scale = _PCAP_MAGICS[header[:4]]
            major, minor, _, _, self._snaplen, linktype = struct.unpack_from(
                endian + "HHIIII", header, 4
            )
            if (major, minor) != (2, 4) or self._snaplen == 0:
                raise CaptureError("仅支持具有有效抓取长度的经典 PCAP 2.4。")
            self.linktype = linktype & 0xFFFF
            self._record = struct.Struct(endian + "IIII")
        except BaseException:
            self.close()
            raise
        return self

    def __iter__(self):
        if self._stream is None:
            raise CaptureError("请先打开 PCAP 文件。")
        index = 0
        while header := self._stream.read(self._record.size):
            index += 1
            if len(header) != self._record.size:
                raise CaptureError(f"PCAP 第 {index} 条记录的头部不完整。")
            seconds, fraction, length, original_length = self._record.unpack(header)
            if fraction >= self._scale or length > min(self._snaplen, _MAX_FILE_FRAME, original_length):
                raise CaptureError(f"PCAP 第 {index} 条记录的时间戳或长度无效。")
            data = self._stream.read(length)
            if len(data) != length:
                raise CaptureError(f"PCAP 第 {index} 条记录的数据不完整。")
            yield Frame(seconds + fraction / self._scale, data, original_length)

    def close(self):
        if self._stream is not None:
            self._stream.close()
            self._stream = None

    def __exit__(self, exc_type, exc, traceback):
        self.close()


def write_pcap(path, linktype: int, frames):
    """Write little-endian PCAP 2.4 and replace the destination on success."""
    if not 0 <= linktype <= 0xFFFF:
        raise CaptureError("PCAP 链路类型超出范围。")
    destination = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=destination.parent, prefix=".pcap-", suffix=".tmp", delete=False
        ) as stream:
            temporary = Path(stream.name)
            stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, _LIVE_SNAPLEN, linktype))
            snaplen = _LIVE_SNAPLEN
            for frame in frames:
                length = len(frame.data)
                if length > _MAX_FILE_FRAME or not length <= frame.original_length <= 0xFFFFFFFF:
                    raise CaptureError("待写入的数据包长度无效。")
                if not math.isfinite(frame.timestamp) or not 0 <= frame.timestamp < 2**32:
                    raise CaptureError("待写入的数据包时间戳超出范围。")
                seconds, microseconds = divmod(round(frame.timestamp * 1_000_000), 1_000_000)
                if seconds > 0xFFFFFFFF:
                    raise CaptureError("待写入的数据包时间戳超出范围。")
                stream.write(struct.pack("<IIII", seconds, microseconds, length, frame.original_length))
                stream.write(frame.data)
                snaplen = max(snaplen, length)
            if snaplen != _LIVE_SNAPLEN:
                stream.seek(16)
                stream.write(struct.pack("<I", snaplen))
        temporary.replace(destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
