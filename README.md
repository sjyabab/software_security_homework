# 实验 1B 安全文件传输

使用 Python 标准库实现的 SFT1 文件传输协议、双向 TLS 服务端和 Tkinter 图形客户端。

## 功能

- 多用户证书身份认证及独立文件空间。
- 持续 TCP/TLS 连接，5 秒应用层心跳和 SO_KEEPALIVE。
- 上传与下载采用 SHA-256 校验、临时文件和原子替换。
- 上传和下载断点续传，校验已传前缀，服务器重启后可恢复上传。
- GUI 两路并行任务，可同时上传和下载，支持暂停及继续。
- 每用户、每方向共享带宽配额，Alice 为 1 MiB/s，Bob 为 256 KiB/s。
- 有界帧解析、连接与请求频率限制、握手超时、文件数和空间上限。

## 环境

Windows，Python 3.10 或更新版本，含 Tkinter。应用无需 pip 依赖。
初始化证书需要 OpenSSL 3.x。程序先查找 PATH 中的 openssl，也会查找 Git for Windows 安装路径中的 OpenSSL。

## 快速启动

在源码目录运行以下命令。

```powershell
python -B launch_demo.py
```

首次运行自动创建 `runtime`，生成本机独立 CA、服务器及 Alice/Bob 证书，设置运行目录 ACL，启动回环服务器并打开 GUI。

1. 点击 Alice 或 Bob，点击连接。
2. 上传 `runtime/samples` 中的一个或多个文件。
3. 选中传输任务，点击暂停所选，再点击继续所选。
4. 选中服务器文件，点击下载所选文件并选择下载目录。
5. 上传与下载任务可并行执行。关闭此演示窗口会停止其启动的服务器。

初始化只接受尚不存在的目录，避免覆盖已有证书及数据。如果默认端口 8766 被占用，可先停止旧实例，或手动初始化时指定其他端口。

## 分开运行

在三个终端中分别启动初始化、服务端和客户端。初始化执行一次。

```powershell
python -B setup_demo.py --runtime runtime --port 8766
python -B server.py --config runtime/server/config.json
python -B gui.py --profile runtime/clients/alice/profile.json
```

另一个客户端可以选择 `runtime/clients/bob/profile.json`。跨主机使用时，需要同时配置服务端监听地址、证书 SAN、客户端主机名及防火墙。默认演示绑定 `127.0.0.1`，证书覆盖 localhost 与回环地址。

## 自动化测试

```powershell
python -B test_system.py
```

测试独立生成临时证书，通过真实 TCP/TLS 验证文件往返、服务器重启续传、下载续传、用户隔离、路径校验、错误证书拒绝、拆包粘包、原子替换、同名冲突、并发限速、连接上限、保活、握手超时及 Windows 并发小文件收尾。测试结束后清理临时目录。

## 文件结构

| 文件 | 用途 |
| --- | --- |
| `protocol.py` | 20 字节帧头、JSON 与二进制载荷收发、输入校验 |
| `server.py` | 双向 TLS、身份授权、用户空间、资源限制与限速 |
| `client.py` | 连接保活、完整性校验、上传与下载续传 |
| `gui.py` | 图形客户端与并行任务队列 |
| `setup_demo.py` | 生成本机 PKI、用户配置与样例 |
| `secure_runtime.ps1` | Windows 运行目录 ACL |
| `launch_demo.py` | 一键本机演示入口 |
| `test_system.py` | 真实 TLS 集成测试 |

## 协议与限制

SFT1 帧头按网络字节序编码 Magic、版本、操作码、标志、请求编号、JSON 长度和载荷长度。操作包含 HELLO、PING、LIST、PUT_BEGIN、PUT_CHUNK、PUT_FINISH、GET_BEGIN、GET_CHUNK、RELEASE 和 QUIT。文件传输完成后连接继续保留。

- 单帧 JSON 上限 16 KiB，数据块上限 64 KiB，单文件上限 64 MiB。
- 每用户空间 256 MiB，文件和待传名额上限 256。
- 默认全局最多 16 个连接，单 IP 最多 12 个，单用户最多 4 个。
- 握手期限 4 秒，整帧期限 15 秒，单连接每秒最多 150 次请求。
- 每个 IP 每 60 秒最多发起 30 次新连接。
- 支持单层文件名，同名文件在传输时使用排他锁。

应用层限制可减少资源耗尽风险。公网链路型 DDoS 需要额外网络层防护。证书指纹白名单在服务器启动时加载，修改用户配置或撤销证书后需重启服务。

`runtime/authority` 保存 CA 私钥，服务器运行只需要 `runtime/server` 中的配置和证书。用户只应获得自己的客户端配置与凭据。生成的私钥、证书、断点和运行时数据已由 `.gitignore` 排除。

## 参考

- [Python ssl](https://docs.python.org/3/library/ssl.html)
- [OpenSSL req](https://docs.openssl.org/3.5/man1/openssl-req/)
- [Microsoft icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
