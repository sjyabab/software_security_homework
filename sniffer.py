"""Tk desktop packet viewer for the network diagnostics lab."""

import os
import queue
import threading
import tkinter as tk
from collections import OrderedDict
from dataclasses import dataclass
from tkinter import filedialog, messagebox, ttk

from capture import CaptureError, Frame, LiveCapture, PcapReader, list_interfaces, write_pcap
from decoder import DecodedPacket, decode_packet
from demo_data import DEMO_LINKTYPE, demo_packets


LIMIT = 3000
PCAP_BYTE_LIMIT = 64 * 1024 * 1024
HEX_PREVIEW = 1024
FILTERS = {
    '全部': '', 'HTTP': 'HTTP', 'TCP': 'TCP', 'UDP': 'UDP', 'IPv4': 'IPV4',
    'IPv6': 'IPV6', 'ICMP': 'ICMP', 'ICMPv6': 'ICMPV6', 'DNS': 'DNS',
    'ARP': 'ARP', 'VLAN': 'VLAN',
}
BG, INK, MUTED, BLUE = '#edf2f8', '#15253a', '#48617a', '#174d8c'


@dataclass(frozen=True)
class Record:
    frame: Frame
    decoded: DecodedPacket


def endpoint(address, port):
    if port is None:
        return address or '—'
    return f'[{address}]:{port}' if ':' in address else f'{address}:{port}'


def hex_dump(data):
    lines = ['偏移      十六进制字节                                      ASCII']
    for offset in range(0, min(len(data), HEX_PREVIEW), 16):
        chunk = data[offset:offset + 16]
        printable = ''.join(chr(byte) if 32 <= byte < 127 else '.' for byte in chunk)
        lines.append(f'{offset:04X}      {chunk.hex(" ").upper():47}  {printable}')
    if len(data) > HEX_PREVIEW:
        lines.append(f'\n显示前 {HEX_PREVIEW} 字节，导出时保留完整捕获数据。')
    return '\n'.join(lines)


def capture_worker(name, bpf, stop, outbox):
    skipped = 0
    try:
        with LiveCapture(name, bpf) as capture:
            outbox.put(('ready', capture.linktype))
            while not stop.is_set():
                frame = capture.read()
                if frame is None:
                    stop.wait(0.008)
                    continue
                try:
                    outbox.put_nowait(('frame', frame))
                except queue.Full:
                    skipped += 1
    except (CaptureError, OSError) as exc:
        outbox.put(('error', str(exc)))
    finally:
        outbox.put(('done', skipped))


class Sniffer:
    def __init__(self, root):
        self.root = root
        self.records = OrderedDict()
        self.interfaces = []
        self.linktype = None
        self.first_time = None
        self.serial = 0
        self.discarded = 0
        self.worker_skipped = 0
        self.flow_key = None
        self.stop_signal = None
        self.outbox = None
        self.closing = False
        self.source = '等待数据'
        self.notice = tk.StringVar(value='加载示例、打开 PCAP，或选择网卡开始抓包。')
        self.counts = tk.StringVar()
        self.flow_label = tk.StringVar(value='未限定 TCP 流')
        self.display_filter = tk.StringVar(value='全部')
        self.bpf = tk.StringVar(value='tcp port 8765')
        self.root.title('实验 1A  网络嗅探器')
        self.root.geometry('1140x720')
        self.root.minsize(950, 580)
        self.root.configure(background=BG)
        self._build()
        self._counts()
        self.refresh_interfaces()
        self.root.protocol('WM_DELETE_WINDOW', self.close)

    def _build(self):
        style = ttk.Style(self.root)
        style.theme_use('clam')
        style.configure('.', font=('Microsoft YaHei UI', 10), foreground=INK)
        style.configure('TFrame', background=BG)
        style.configure('TLabel', background=BG)
        style.configure('Caption.TLabel', foreground=MUTED)
        style.configure('Section.TLabel', font=('Microsoft YaHei UI', 10, 'bold'), foreground=BLUE)
        style.configure('TButton', padding=(8, 5), background='#ffffff')
        style.configure('Primary.TButton', foreground='white', background=BLUE)
        style.map('Primary.TButton', background=[('disabled', '#8496ab'), ('active', '#2664a8')])
        style.configure('Treeview', background='#ffffff', fieldbackground='#ffffff', rowheight=25)
        style.configure('Treeview.Heading', font=('Microsoft YaHei UI', 9, 'bold'),
                        background='#dfe9f5', padding=(5, 5))
        style.map('Treeview', background=[('selected', '#2763a4')], foreground=[('selected', '#ffffff')])

        banner = tk.Frame(self.root, background='#142c48', padx=19, pady=10)
        banner.pack(fill='x')
        tk.Label(banner, text='网络嗅探器', font=('Microsoft YaHei UI', 19, 'bold'),
                 background='#142c48', foreground='white').pack(side='left')
        tk.Label(banner, text='实验 1A    ·    抓包 / 协议解析 / TCP 流追踪',
                 font=('Microsoft YaHei UI', 10), background='#142c48', foreground='#c4d6ec',
                 padx=18).pack(side='left', anchor='s', pady=5)

        controls = ttk.Frame(self.root, padding=(14, 7))
        controls.pack(fill='x')
        controls.columnconfigure(1, weight=2)
        controls.columnconfigure(4, weight=1)
        ttk.Label(controls, text='实时网卡').grid(row=0, column=0, padx=(0, 6))
        self.interface = ttk.Combobox(controls, state='readonly', width=31)
        self.interface.grid(row=0, column=1, sticky='ew', padx=(0, 6))
        self.refresh_button = ttk.Button(controls, text='刷新网卡', command=self.refresh_interfaces)
        self.refresh_button.grid(row=0, column=2, padx=(0, 12))
        ttk.Label(controls, text='捕获 BPF').grid(row=0, column=3, padx=(0, 6))
        self.bpf_entry = ttk.Entry(controls, textvariable=self.bpf, width=18)
        self.bpf_entry.grid(row=0, column=4, sticky='ew', padx=(0, 6))
        self.start_button = ttk.Button(controls, text='开始抓包', style='Primary.TButton', command=self.start)
        self.start_button.grid(row=0, column=5, padx=(0, 6))
        self.stop_button = ttk.Button(controls, text='停止', command=self.stop, state='disabled', width=5)
        self.stop_button.grid(row=0, column=6)

        actions = ttk.Frame(self.root, padding=(14, 0, 14, 8))
        actions.pack(fill='x')
        self.demo_button = ttk.Button(actions, text='加载示例', command=self.load_demo)
        self.demo_button.pack(side='left', padx=(0, 6))
        self.open_button = ttk.Button(actions, text='打开 PCAP', command=self.open_file)
        self.open_button.pack(side='left', padx=(0, 6))
        self.export_button = ttk.Button(actions, text='导出 PCAP', command=self.export_file, state='disabled')
        self.export_button.pack(side='left', padx=(0, 18))
        ttk.Label(actions, text='显示筛选').pack(side='left', padx=(0, 6))
        self.filter_box = ttk.Combobox(actions, values=tuple(FILTERS), width=9,
                                       state='readonly', textvariable=self.display_filter)
        self.filter_box.pack(side='left', padx=(0, 9))
        self.filter_box.bind('<<ComboboxSelected>>', self.rebuild)
        self.follow_button = ttk.Button(actions, text='追踪所选 TCP 流', command=self.follow, state='disabled')
        self.follow_button.pack(side='left', padx=(0, 6))
        self.clear_button = ttk.Button(actions, text='清除流筛选', command=self.clear_flow, state='disabled')
        self.clear_button.pack(side='left')

        status = ttk.Frame(self.root, padding=(14, 5, 14, 9))
        status.pack(side='bottom', fill='x')
        ttk.Label(status, textvariable=self.notice, style='Caption.TLabel').pack(side='left')
        ttk.Label(status, textvariable=self.counts, style='Section.TLabel').pack(side='right')

        workspace = ttk.Panedwindow(self.root, orient='vertical')
        workspace.pack(fill='both', expand=True, padx=14)
        packet_panel = ttk.Frame(workspace, padding=(0, 0, 0, 4))
        workspace.add(packet_panel, weight=4)
        top = ttk.Frame(packet_panel)
        top.pack(fill='x', pady=(0, 4))
        ttk.Label(top, text='01  数据包列表', style='Section.TLabel').pack(side='left')
        ttk.Label(top, textvariable=self.flow_label, style='Caption.TLabel').pack(side='right')
        columns = (
            ('id', '编号', 52, 'e'), ('time', '相对时间 / s', 103, 'e'),
            ('src', '源地址', 175, 'w'), ('dst', '目的地址', 175, 'w'),
            ('proto', '协议', 83, 'center'), ('size', '长度 / B', 78, 'e'),
            ('summary', '摘要', 386, 'w'),
        )
        self.table = ttk.Treeview(packet_panel, columns=[col[0] for col in columns],
                                  show='headings', selectmode='browse', height=10)
        for key, title, width, anchor in columns:
            self.table.heading(key, text=title, anchor=anchor)
            self.table.column(key, width=width, minwidth=48, stretch=key in ('src', 'dst', 'summary'), anchor=anchor)
        self.table.tag_configure('even', background='#f2f7fc')
        self.table.tag_configure('HTTP', foreground='#14508f')
        self._scrollable(packet_panel, self.table)
        self.table.bind('<<TreeviewSelect>>', self.show_selected)

        inspectors = ttk.Panedwindow(workspace, orient='horizontal')
        workspace.add(inspectors, weight=3)
        details_panel = ttk.Frame(inspectors, padding=(0, 0, 4, 0))
        inspectors.add(details_panel, weight=1)
        ttk.Label(details_panel, text='02  协议详情', style='Section.TLabel').pack(anchor='w', pady=(0, 4))
        self.details = ttk.Treeview(details_panel, show='tree', selectmode='none', height=8)
        self._scrollable(details_panel, self.details)

        bytes_panel = ttk.Frame(inspectors, padding=(4, 0, 0, 0))
        inspectors.add(bytes_panel, weight=2)
        ttk.Label(bytes_panel, text='03  原始字节', style='Section.TLabel').pack(anchor='w', pady=(0, 4))
        self.raw = tk.Text(bytes_panel, font=('Consolas', 10), width=64, height=8, wrap='none',
                           foreground=INK, background='white', relief='flat', padx=8, pady=4, state='disabled')
        self._scrollable(bytes_panel, self.raw, horizontal=True)
        self._show_raw('选择一个数据包以查看原始字节。')

    @staticmethod
    def _scrollable(parent, widget, horizontal=False):
        if horizontal:
            xscroll = ttk.Scrollbar(parent, orient='horizontal', command=widget.xview)
            widget.configure(xscrollcommand=xscroll.set)
            xscroll.pack(side='bottom', fill='x')
        yscroll = ttk.Scrollbar(parent, orient='vertical', command=widget.yview)
        widget.configure(yscrollcommand=yscroll.set)
        yscroll.pack(side='right', fill='y')
        widget.pack(side='left', fill='both', expand=True)

    def refresh_interfaces(self):
        try:
            self.interfaces = list_interfaces()
        except (CaptureError, OSError):
            self.interfaces = []
            self.notice.set('Npcap 不可用。可加载示例或打开 PCAP。')
        else:
            self.notice.set('请选择网卡及 BPF。' if self.interfaces else '未发现可用网卡。')
        self.interface['values'] = [item.description or item.name for item in self.interfaces]
        self.interface.set('')
        if self.interfaces:
            default = next((i for i, item in enumerate(self.interfaces) if 'loopback' in item.name.lower()), 0)
            self.interface.current(default)
        self.start_button.configure(state='normal' if self.interfaces else 'disabled')

    def start(self):
        index = self.interface.current()
        if index < 0 or self.outbox is not None:
            return
        name = self.interfaces[index].name
        bpf = self.bpf.get().strip()
        self.stop_signal = threading.Event()
        self.outbox = queue.Queue(maxsize=512)
        self._set_running(True)
        self.notice.set('正在打开实时网卡…')
        threading.Thread(target=capture_worker, args=(name, bpf, self.stop_signal, self.outbox), daemon=True).start()
        self.root.after(25, self.poll_capture)

    def stop(self):
        if self.stop_signal is not None:
            self.stop_signal.set()
            self.stop_button.configure(state='disabled')
            self.notice.set('正在停止抓包…')

    def _set_running(self, running):
        state = 'disabled' if running else 'normal'
        for button in (self.refresh_button, self.demo_button, self.open_button, self.bpf_entry):
            button.configure(state=state)
        self.interface.configure(state='disabled' if running else 'readonly')
        self.start_button.configure(state='normal' if not running and self.interfaces else 'disabled')
        self.stop_button.configure(state='normal' if running else 'disabled')
        self._counts()

    def poll_capture(self):
        for _ in range(120):
            try:
                event, value = self.outbox.get_nowait()
            except queue.Empty:
                break
            if event == 'ready':
                self._reset(value, '实时捕获')
                self.notice.set('正在实时抓包。')
            elif event == 'frame':
                self._add(value)
            elif event == 'error':
                self.notice.set('抓包失败。检查网卡、Npcap 权限和 BPF。')
                messagebox.showerror('抓包失败', value, parent=self.root)
            elif event == 'done':
                self.worker_skipped = value
                self.outbox = self.stop_signal = None
                if self.closing:
                    self.root.destroy()
                    return
                self._set_running(False)
                if not self.notice.get().startswith('抓包失败'):
                    self.notice.set('实时抓包已停止。')
                return
        self._counts()
        self.root.after(25, self.poll_capture)

    def close(self):
        if self.stop_signal is None:
            self.root.destroy()
        else:
            self.closing = True
            self.stop()

    def load_demo(self):
        self._reset(DEMO_LINKTYPE, '内置样例')
        for packet in demo_packets():
            self._add(Frame(*packet))
        self.notice.set('已加载内置合成样例。')
        self._counts()
        self._select_first()

    def open_file(self):
        path = filedialog.askopenfilename(parent=self.root, title='打开 PCAP',
                                          filetypes=[('PCAP', '*.pcap'), ('所有文件', '*.*')])
        if path:
            self.load_pcap(path)

    def load_pcap(self, path):
        try:
            with PcapReader(path) as capture:
                linktype = capture.linktype
                packets = []
                total_bytes = 0
                limited = False
                for frame in capture:
                    total_bytes += len(frame.data)
                    if len(packets) >= LIMIT or total_bytes > PCAP_BYTE_LIMIT:
                        limited = True
                        break
                    packets.append(frame)
        except (CaptureError, OSError) as exc:
            messagebox.showerror('无法打开 PCAP', str(exc), parent=self.root)
            return
        self._reset(linktype, 'PCAP 文件')
        for frame in packets:
            self._add(frame)
        suffix = f'，达到载入上限，已载入前 {len(packets)} 包' if limited else ''
        self.notice.set(f'已打开 {os.path.basename(path)}{suffix}。')
        self._counts()
        self._select_first()

    def export_file(self):
        path = filedialog.asksaveasfilename(parent=self.root, title='导出全部保留数据包',
                                            defaultextension='.pcap', filetypes=[('PCAP', '*.pcap')])
        if path:
            self.save_pcap(path)

    def save_pcap(self, path):
        try:
            write_pcap(path, self.linktype, (item.frame for item in self.records.values()))
        except (CaptureError, OSError) as exc:
            messagebox.showerror('无法导出 PCAP', str(exc), parent=self.root)
            return
        self.notice.set(f'已导出 {len(self.records)} 个数据包。')

    def _reset(self, linktype, source):
        self.records.clear()
        self.linktype = linktype
        self.first_time = None
        self.serial = self.discarded = self.worker_skipped = 0
        self.source = source
        self.flow_key = None
        self.display_filter.set('全部')
        self.rebuild()

    def _add(self, frame):
        self.serial += 1
        if self.first_time is None:
            self.first_time = frame.timestamp
        record = Record(frame, decode_packet(frame.data, self.linktype))
        key = str(self.serial)
        if len(self.records) == LIMIT:
            oldest, _ = self.records.popitem(last=False)
            self.discarded += 1
            if self.table.exists(oldest):
                self.table.delete(oldest)
        self.records[key] = record
        if self._matches(record):
            self._show_row(key, record)

    def _matches(self, record):
        token = FILTERS[self.display_filter.get()]
        return ((not token or token in record.decoded.protocols)
                and (self.flow_key is None or self.flow_key == record.decoded.flow_key))

    def _show_row(self, key, record):
        frame, packet = record.frame, record.decoded
        summary = packet.summary or packet.warning or '—'
        if self.flow_key:
            side = (packet.source, packet.source_port)
            summary = ('A → B  ' if side == self.flow_key[1] else 'B → A  ') + summary
        self.table.insert('', 'end', iid=key, values=(
            key, f'{frame.timestamp - self.first_time:.6f}',
            endpoint(packet.source, packet.source_port), endpoint(packet.destination, packet.destination_port),
            packet.protocol, frame.original_length, summary,
        ), tags=(('even' if int(key) % 2 == 0 else 'odd'), packet.protocol))

    def _counts(self):
        extra = ''
        if self.discarded or self.worker_skipped:
            extra = f'  |  淘汰 {self.discarded} · 队列丢弃 {self.worker_skipped}'
        self.counts.set(f'{self.source}  |  显示 {len(self.table.get_children())} / 保留 {len(self.records)}{extra}')
        self.export_button.configure(state='normal' if self.records and self.outbox is None else 'disabled')

    def _select_first(self):
        children = self.table.get_children()
        if children:
            self.table.selection_set(children[0])
            self.table.see(children[0])
        self.show_selected()

    def rebuild(self, _event=None):
        selected = self.table.selection()
        self.table.delete(*self.table.get_children())
        for key, record in self.records.items():
            if self._matches(record):
                self._show_row(key, record)
        if selected and self.table.exists(selected[0]):
            self.table.selection_set(selected[0])
            self.table.see(selected[0])
            self.show_selected()
        else:
            self._select_first()
        if self.flow_key:
            _, a, b = self.flow_key
            self.flow_label.set(f'A  {endpoint(*a)}    ↔    B  {endpoint(*b)}')
        else:
            self.flow_label.set('未限定 TCP 流')
        self.clear_button.configure(state='normal' if self.flow_key else 'disabled')
        self._counts()

    def selected(self):
        selection = self.table.selection()
        return self.records.get(selection[0]) if selection else None

    def follow(self):
        record = self.selected()
        if record and record.decoded.flow_key:
            self.flow_key = record.decoded.flow_key
            self.display_filter.set('全部')
            self.rebuild()

    def clear_flow(self):
        self.flow_key = None
        self.rebuild()

    def _show_raw(self, text):
        self.raw.configure(state='normal')
        self.raw.delete('1.0', 'end')
        self.raw.insert('1.0', text)
        self.raw.configure(state='disabled')

    def show_selected(self, _event=None):
        record = self.selected()
        self.follow_button.configure(state='normal' if record and record.decoded.flow_key else 'disabled')
        self.details.delete(*self.details.get_children())
        if not record:
            self._show_raw('选择一个数据包以查看原始字节。')
            return
        frame, packet = record.frame, record.decoded
        self.details.insert('', 'end', text=f'帧长 {frame.original_length} B · 已捕获 {len(frame.data)} B')
        if packet.warning:
            self.details.insert('', 'end', text=packet.warning)
        for index, (layer, fields) in enumerate(packet.layers):
            node = self.details.insert('', 'end', text=layer, open=index == len(packet.layers) - 1)
            for name, value in fields:
                self.details.insert(node, 'end', text=f'{name}  {value}')
        self._show_raw(hex_dump(frame.data))


if __name__ == '__main__':
    root = tk.Tk()
    Sniffer(root)
    root.mainloop()
