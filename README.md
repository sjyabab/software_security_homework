# 软件与系统安全实验 1A 网络嗅探器

这个 Windows 图形工具可以采集本机网络数据包，也可以读取经典 PCAP 文件。界面同时显示包列表、协议字段和十六进制字节。

## 启动

需要 Windows 和自带 Tkinter 的 Python 3.10 或更新版本。离线查看只用 Python 标准库。实时抓包还需要安装 [Npcap](https://npcap.com/#download)。

在仓库目录运行

```powershell
python -B sniffer.py
```

## 离线查看

1. 点击「加载示例」，载入 20 个合成数据包。
2. 使用「显示筛选」查看 HTTP、TCP、UDP、IPv4、IPv6、ICMP、ICMPv6、DNS、ARP 或 VLAN 数据包。
3. 选中 TCP 包后点击「追踪所选 TCP 流」，查看这一对 IP 地址和端口之间的双向报文。摘要标记报文方向。
4. 「导出 PCAP」保存当前保留的全部数据包。「打开 PCAP」可以重新读取导出的经典 PCAP 文件。

## 回环抓包

在一个空目录启动绑定于本机回环地址的 HTTP 服务。

```powershell
python -m http.server 8765 --bind 127.0.0.1
```

在图形界面点击「刷新网卡」，选择 Npcap 回环适配器，填写捕获 BPF `tcp port 8765` 并开始抓包。另开一个终端发送请求。

```powershell
curl.exe --noproxy '*' http://127.0.0.1:8765/
```

回到界面点击「停止」。捕获 BPF 决定哪些包进入程序。显示筛选作用于已经保留的数据，可随时切换。

## 源码与范围

| 文件 | 职责 |
| --- | --- |
| `sniffer.py` | 图形界面、筛选和流追踪 |
| `capture.py` | Npcap 接口及经典 PCAP 导入导出 |
| `decoder.py` | 以太网与 Npcap 回环帧的协议解析 |
| `demo_data.py` | 内置合成样例 |

程序从单个 TCP 段识别 HTTP/1.x 起始行。流追踪按端点归组，不重组 TCP 字节流，也不解密 TLS。界面最多保留 3,000 包，导入另有 64 MiB 的捕获数据上限。
