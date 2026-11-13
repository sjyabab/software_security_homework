"""One command creates local demo identities, starts the server and opens Tk."""
import argparse
from pathlib import Path
import threading
import tkinter as tk

from gui import App
from server import Server
from setup_demo import initialize


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', default='runtime')
    args = parser.parse_args()
    runtime = Path(args.runtime).resolve()
    if not runtime.exists():
        print('正在生成本机演示证书与样例…', flush=True)
        initialize(runtime)
    server = Server(runtime / 'server' / 'config.json')
    threading.Thread(target=server.serve, daemon=True).start()
    print(f'本地服务器已启动 127.0.0.1:{server.port}', flush=True)
    root = tk.Tk()
    App(root, runtime, on_closed=server.close)
    try:
        root.mainloop()
    finally:
        server.close()


if __name__ == '__main__':
    main()
