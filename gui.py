"""Windows-friendly graphical client; network operations run outside Tk."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from client import Client, Paused


def size_text(value):
    return f'{value / 1048576:.2f} MiB' if value >= 1048576 else f'{value / 1024:.1f} KiB'


@dataclass
class Transfer:
    key: str
    direction: str
    name: str
    path: Path
    status: str = '排队'
    done: int = 0
    total: int = 0
    cancel: threading.Event = field(default_factory=threading.Event)


class App:
    def __init__(self, root, runtime='runtime', profile=None, on_closed=None):
        self.root = root
        self.runtime = Path(runtime).resolve()
        self.on_closed = on_closed
        self.control = None
        self.clients = []
        self.pool = None
        self.available = queue.Queue()
        self.events = queue.Queue()
        self.tasks = {}
        self.counter = 0
        self.closing = False
        self.busy = False
        self.refresh_pending = False
        self.profile = tk.StringVar(value=str(profile or self.runtime / 'clients' / 'alice' / 'profile.json'))
        self.status = tk.StringVar(value='选择证书身份后连接服务器')
        self.identity = tk.StringVar(value='未连接')
        self.summary = tk.StringVar(value='最多 2 个并行任务 · 支持暂停与续传')
        root.title('实验 1B  安全文件传输')
        root.geometry('1200x760')
        root.minsize(1040, 650)
        root.configure(bg='#edf3f8')
        self.build()
        root.protocol('WM_DELETE_WINDOW', self.close)
        root.after(60, self.drain)

    def build(self):
        style = ttk.Style(self.root)
        style.theme_use('clam')
        style.configure('.', font=('Microsoft YaHei UI', 10), foreground='#182f46')
        style.configure('TFrame', background='#edf3f8')
        style.configure('TLabel', background='#edf3f8')
        style.configure('TButton', padding=(10, 6), background='white')
        style.configure('Primary.TButton', background='#155c75', foreground='white')
        style.map('Primary.TButton', background=[('disabled', '#809aa8'), ('active', '#227f97')])
        style.configure('Section.TLabel', font=('Microsoft YaHei UI', 11, 'bold'), foreground='#155c75')
        style.configure('Treeview', rowheight=28, background='white', fieldbackground='white')
        style.configure('Treeview.Heading', background='#dce9f0', font=('Microsoft YaHei UI', 10, 'bold'))
        style.map('Treeview', background=[('selected', '#226e8a')], foreground=[('selected', 'white')])
        banner = tk.Frame(self.root, bg='#123549', padx=20, pady=12)
        banner.pack(fill='x')
        tk.Label(banner, text='安全文件传输', font=('Microsoft YaHei UI', 21, 'bold'),
                 bg='#123549', fg='white').pack(side='left')
        tk.Label(banner, text='SFT1  ·  双向 TLS  ·  断点续传  ·  并行传输',
                 font=('Microsoft YaHei UI', 11), bg='#123549', fg='#c3dce7', padx=24).pack(side='left')
        controls = ttk.Frame(self.root, padding=(16, 10))
        controls.pack(fill='x')
        ttk.Label(controls, text='身份配置').pack(side='left', padx=(0, 8))
        self.profile_box = ttk.Entry(controls, textvariable=self.profile)
        self.profile_box.pack(side='left', fill='x', expand=True)
        self.browse_button = ttk.Button(controls, text='选择…', command=self.choose_profile)
        self.browse_button.pack(side='left', padx=6)
        self.alice_button = ttk.Button(controls, text='Alice', command=lambda: self.select_user('alice'))
        self.alice_button.pack(side='left', padx=(0, 6))
        self.bob_button = ttk.Button(controls, text='Bob', command=lambda: self.select_user('bob'))
        self.bob_button.pack(side='left', padx=(0, 10))
        self.connect_button = ttk.Button(controls, text='连接', style='Primary.TButton', command=self.connect)
        self.connect_button.pack(side='left', padx=(0, 6))
        self.disconnect_button = ttk.Button(controls, text='断开', command=self.disconnect, state='disabled')
        self.disconnect_button.pack(side='left')
        connection = ttk.Frame(self.root, padding=(16, 0, 16, 8))
        connection.pack(fill='x')
        ttk.Label(connection, textvariable=self.identity, style='Section.TLabel').pack(side='left')
        ttk.Label(connection, textvariable=self.summary).pack(side='right')

        footer = ttk.Frame(self.root, padding=(16, 8))
        footer.pack(side='bottom', fill='x')
        ttk.Label(footer, textvariable=self.status).pack(anchor='w')
        body = ttk.Panedwindow(self.root, orient='vertical')
        body.pack(fill='both', expand=True, padx=16)
        remote = ttk.Frame(body)
        body.add(remote, weight=3)
        actions = ttk.Frame(remote)
        actions.pack(fill='x', pady=(0, 7))
        ttk.Label(actions, text='服务器文件', style='Section.TLabel').pack(side='left')
        self.refresh_button = ttk.Button(actions, text='刷新列表', command=self.refresh, state='disabled')
        self.refresh_button.pack(side='right')
        self.download_button = ttk.Button(actions, text='下载所选文件', command=self.choose_download, state='disabled')
        self.download_button.pack(side='right', padx=6)
        self.upload_button = ttk.Button(actions, text='上传文件…', command=self.choose_upload, state='disabled')
        self.upload_button.pack(side='right')
        self.remote_table = self.table(remote, [('name', '文件名', 540), ('size', '大小', 160), ('space', '用户空间', 200)])

        transfer = ttk.Frame(body, padding=(0, 9, 0, 0))
        body.add(transfer, weight=4)
        taskbar = ttk.Frame(transfer)
        taskbar.pack(fill='x', pady=(0, 7))
        ttk.Label(taskbar, text='传输任务', style='Section.TLabel').pack(side='left')
        self.resume_button = ttk.Button(taskbar, text='继续所选', command=self.resume_selected, state='disabled')
        self.resume_button.pack(side='right')
        self.pause_button = ttk.Button(taskbar, text='暂停所选', command=self.pause_selected, state='disabled')
        self.pause_button.pack(side='right', padx=6)
        self.task_table = self.table(transfer, [('name', '文件名', 290), ('direction', '方向', 90),
                                                ('status', '状态', 140), ('progress', '进度', 95),
                                                ('bytes', '已传 / 总量', 230)])
        self.task_table.tag_configure('success', foreground='#167049')
        self.task_table.tag_configure('error', foreground='#ac3c2f')
        log_panel = ttk.Frame(body, padding=(0, 8, 0, 0))
        body.add(log_panel, weight=1)
        ttk.Label(log_panel, text='校验与会话记录', style='Section.TLabel').pack(anchor='w', pady=(0, 4))
        self.log_box = tk.Text(log_panel, height=4, wrap='word', state='disabled', relief='flat',
                               font=('Consolas', 10), padx=10, pady=6, bg='#f7fafc', fg='#29485d')
        self.log_box.pack(fill='both', expand=True)

    @staticmethod
    def table(parent, columns):
        box = ttk.Frame(parent)
        box.pack(fill='both', expand=True)
        view = ttk.Treeview(box, columns=[col[0] for col in columns], show='headings')
        for key, label, width in columns:
            view.heading(key, text=label, anchor='w')
            view.column(key, width=width, minwidth=70, stretch=key == 'name')
        scroll = ttk.Scrollbar(box, command=view.yview)
        view.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right', fill='y')
        view.pack(side='left', fill='both', expand=True)
        return view

    def log(self, value):
        self.log_box.configure(state='normal')
        self.log_box.insert('end', value + '\n')
        if int(self.log_box.index('end-1c').split('.')[0]) > 250:
            self.log_box.delete('1.0', '51.0')
        self.log_box.see('end')
        self.log_box.configure(state='disabled')

    def select_user(self, user):
        self.profile.set(str(self.runtime / 'clients' / user / 'profile.json'))

    def choose_profile(self):
        path = filedialog.askopenfilename(parent=self.root, filetypes=[('用户配置', '*.json')])
        if path:
            self.profile.set(path)

    def set_controls(self, connected, busy=False):
        self.busy = busy
        for widget in (self.profile_box, self.browse_button, self.alice_button, self.bob_button, self.connect_button):
            widget.configure(state='disabled' if connected or busy else 'normal')
        for widget in (self.upload_button, self.download_button, self.refresh_button,
                       self.pause_button, self.resume_button, self.disconnect_button):
            widget.configure(state='normal' if connected and not busy else 'disabled')

    def connect(self):
        if self.busy or self.control:
            return
        profile = self.profile.get()
        self.set_controls(False, True)
        self.status.set('正在验证服务器证书与客户端身份…')

        def work():
            connections = []
            try:
                for _ in range(3):
                    connections.append(Client(profile))
                self.events.put(('connected', connections))
            except Exception as exc:
                for connection in connections:
                    connection.close()
                self.events.put(('connect_error', str(exc)))
        threading.Thread(target=work, daemon=True).start()

    def refresh(self):
        if not self.control or self.refresh_pending:
            return
        self.refresh_pending = True
        connection = self.control
        def work():
            try:
                self.events.put(('files', connection, connection.list_files()))
            except Exception as exc:
                self.events.put(('refresh_error', '刷新失败 ' + str(exc)))
        threading.Thread(target=work, daemon=True).start()

    def choose_upload(self):
        paths = filedialog.askopenfilenames(parent=self.root, title='可同时选择多个文件',
                                            initialdir=self.runtime / 'samples')
        self.add_upload(paths)

    def add_upload(self, paths):
        for path in paths:
            self.add_task('上传', Path(path).name, Path(path))

    def choose_download(self):
        names = [self.remote_table.item(key, 'values')[0] for key in self.remote_table.selection()]
        if not names:
            return
        destination = filedialog.askdirectory(parent=self.root, title='选择下载目录',
                                               initialdir=Path(self.profile.get()).parent / 'downloads')
        if not destination:
            return
        for name in names:
            path = Path(destination) / name
            if path.exists() and not messagebox.askyesno('覆盖文件', f'下载完成后替换 {name}？', parent=self.root):
                continue
            self.add_task('下载', name, path)

    def add_task(self, direction, name, path):
        if not self.control or self.busy:
            return
        if len(self.tasks) >= 100:
            self.status.set('任务数量达到 100，请断开后重新连接以清空列表。')
            return
        if any(item.name.casefold() == name.casefold() and item.status in ('排队', '传输中', '暂停中')
               for item in self.tasks.values()):
            self.status.set('同名文件已有传输任务。')
            return
        self.counter += 1
        task = Transfer(str(self.counter), direction, name, Path(path))
        self.tasks[task.key] = task
        self.task_table.insert('', 'end', iid=task.key)
        self.update_task(task)
        self.submit(task)

    def submit(self, task):
        task.cancel.clear()
        task.status = '排队'
        self.update_task(task)
        self.pool.submit(self.transfer, task)

    def transfer(self, task):
        connection = self.available.get()
        try:
            if task.cancel.is_set():
                raise Paused('排队任务已暂停')
            self.events.put(('started', task.key))
            method = connection.upload if task.direction == '上传' else connection.download
            args = (task.path, task.name) if task.direction == '上传' else (task.name, task.path)
            def progress(done, total):
                self.events.put(('progress', task.key, done, total))
            result = method(*args, cancel=task.cancel, progress=progress)
            self.events.put(('complete', task.key, result))
        except Paused as exc:
            self.events.put(('paused', task.key, str(exc)))
        except Exception as exc:
            self.events.put(('failed', task.key, str(exc)))
        finally:
            self.available.put(connection)

    def update_task(self, task):
        percent = task.done * 100 / task.total if task.total else (100 if task.status == '完成' else 0)
        self.task_table.item(task.key, values=(task.name, task.direction, task.status,
                            f'{percent:.1f}%', f'{size_text(task.done)} / {size_text(task.total)}'),
                            tags=('success' if task.status == '完成' else 'error' if task.status == '失败' else '',))
        count = sum(t.status == '完成' for t in self.tasks.values())
        self.summary.set(f'已完成 {count} / {len(self.tasks)}    ·    2 路并行传输')

    def pause_selected(self):
        for key in self.task_table.selection():
            task = self.tasks[key]
            if task.status in ('排队', '传输中'):
                task.cancel.set()
                task.status = '暂停中'
                self.update_task(task)

    def resume_selected(self):
        for key in self.task_table.selection():
            task = self.tasks[key]
            if task.status in ('已暂停', '失败'):
                self.submit(task)

    def disconnect(self):
        if self.busy or not self.control:
            return
        self.set_controls(True, True)
        self.status.set('正在停止任务并关闭长连接…')
        for task in self.tasks.values():
            task.cancel.set()
        def work():
            self.pool.shutdown(wait=True)
            for connection in self.clients:
                connection.close()
            self.events.put(('disconnected',))
        threading.Thread(target=work, daemon=True).start()

    def close(self):
        self.closing = True
        if self.busy:
            return
        if self.control:
            self.disconnect()
        else:
            self.finish_close()

    def finish_close(self):
        if self.on_closed:
            self.on_closed()
        self.root.destroy()

    def drain(self):
        for _ in range(500):
            try:
                event = self.events.get_nowait()
            except queue.Empty:
                break
            kind = event[0]
            if kind == 'connected':
                self.clients = event[1]
                self.control = self.clients[0]
                self.pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix='transfer')
                self.available = queue.Queue()
                for connection in self.clients[1:]:
                    self.available.put(connection)
                self.tasks.clear()
                self.task_table.delete(*self.task_table.get_children())
                self.set_controls(True)
                info = self.control.info
                self.identity.set(f'{info["user"]}  ·  {info["tls"]}  ·  双向证书验证通过  ·  每方向 {size_text(info["rate"])}/s')
                self.log(f'连接建立。控制会话 {info["session"]}，另有两条持续传输连接，心跳间隔 5 秒。')
                self.status.set('已连接。可上传、下载或选择多个文件。')
                self.refresh()
                if self.closing:
                    self.disconnect()
            elif kind == 'connect_error':
                self.set_controls(False)
                self.status.set('连接失败 ' + event[1])
                self.log(event[1])
                if self.closing:
                    self.finish_close()
                    return
            elif kind == 'files' and event[1] is self.control:
                self.refresh_pending = False
                self.remote_table.delete(*self.remote_table.get_children())
                for entry in event[2]:
                    self.remote_table.insert('', 'end', values=(entry['name'], size_text(entry['size']), self.control.info['user']))
            elif kind == 'refresh_error':
                self.refresh_pending = False
                self.status.set(event[1])
            elif kind == 'disconnected':
                self.refresh_pending = False
                self.control = None
                self.clients = []
                self.pool = None
                self.set_controls(False)
                self.identity.set('未连接')
                self.status.set('已断开。重新连接后再次添加任务可读取保留的断点。')
                if self.closing:
                    self.finish_close()
                    return
            elif kind in ('started', 'progress', 'complete', 'paused', 'failed'):
                task = self.tasks.get(event[1])
                if task is None:
                    continue
                if kind == 'started':
                    task.status = '传输中'
                elif kind == 'progress':
                    task.done, task.total = event[2:]
                elif kind == 'complete':
                    task.status = '完成'
                    result = event[2]
                    task.done = task.total = result['size']
                    self.log(f'{task.direction} {task.name} 完成，续传起点 {result["resumed"]} B\nSHA-256 {result["sha256"]}')
                    self.refresh()
                else:
                    task.status = '已暂停' if kind == 'paused' else '失败'
                    self.log(task.name + ' ' + event[2])
                self.update_task(task)
        self.root.after(60, self.drain)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', default='runtime')
    parser.add_argument('--profile')
    args = parser.parse_args()
    root = tk.Tk()
    App(root, args.runtime, args.profile)
    root.mainloop()
