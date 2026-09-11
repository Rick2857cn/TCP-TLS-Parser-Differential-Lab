# 本地 TCP/TLS Parser Differential 教学实验室

同一组数据经过不同的缓存与解析逻辑，可能产生不同结果。本项目用 Python 标准库和本机 TCP socket 复现这个现象，不需要管理员权限、第三方包、证书或互联网连接。

> 本项目仅用于本机网络协议教学和防火墙解析器研究。实验全部运行于 127.0.0.1，并使用 `.test` 测试域名。本项目不提供针对真实校园网、运营商网络或第三方网络访问控制系统的规避配置。

## 快速开始

在 PowerShell 中运行：

```powershell
cd C:\Users\36840\campus-firewall-lab
.\scripts\run_demo.ps1
```

脚本选择原生 Python 3.11+，否则选择 3.10+，先执行全部单元测试，再启动真实 loopback Client → Firewall → Server 演示，最后打印总结表。服务在同一进程的线程中运行，使用系统分配的本机端口，退出时关闭 socket 并回收线程；没有后台残留服务。脚本不自动安装 Python 或 WSL。

当前环境 `py -3.14` 是 Python 3.14，`python` 是 Python 3.10。可分别运行：

```powershell
py -3.14 -m unittest discover -v
python -m unittest discover -v
py -3.14 -m lab.demo
```

如果 PowerShell 执行策略禁止 `.ps1`，直接使用以上 Python 命令，无需修改执行策略。

## 文件导航

| 文件 | 用途 |
|---|---|
| `lab/protocol.py` | 帧编码、partial recv、资源限制与完成标记 |
| `lab/server.py` | 收集 Segment，完成后重组并返回 SERVER_OK |
| `lab/firewall_naive.py` | 故意错误的逐块检查，支持 text/tls |
| `lab/firewall_reassembly.py` | 先收集完整消息，再执行策略 |
| `lab/client.py` | 三种基础发送场景 |
| `lab/tls_clienthello.py` | 用 MemoryBIO 生成真实 ClientHello |
| `lab/tls_parser.py` | 有边界检查的最小 SNI 解析器 |
| `lab/sequence.py` | 独立的内存字节偏移教学模块 |
| `lab/demo.py` | 实际本机链路演示与断言 |
| `tests/test_*.py`、`tests/support.py` | unittest 与自动关闭的本机服务辅助函数 |
| `scripts/run_demo.ps1` | 一键测试和演示 |
| `PLAN.md`、`ENVIRONMENT.md` | 实施顺序、环境记录 |

## 手动观察日志

分别打开三个 PowerShell 窗口，先切换到项目目录，再启动：

```powershell
py -3.14 -m lab.server
```

```powershell
py -3.14 -m lab.firewall_naive
```

```powershell
py -3.14 -m lab.firewall_reassembly
```

第四个窗口运行：

```powershell
py -3.14 -m lab.client --case allowed
py -3.14 -m lab.client --case blocked
py -3.14 -m lab.client --case split
py -3.14 -m lab.client --case split --port 19003
```

默认链路为 `Client → 127.0.0.1:19001（Naive）→ 127.0.0.1:19002（Server）`。改进版监听 `127.0.0.1:19003`。`--port` 与 `--upstream-port` 只能改变端口，代码不提供远端地址选项。Ctrl+C 停止手动服务。端口被占用时先检查既有进程，或更换本机端口，不要终止不明进程。

TLS 实际链路演示已包含在 `python -m lab.demo` 中；手动防火墙也支持 `--mode tls`。Server 收取并重组 TLS 字节，但不是完整 TLS 服务端，不完成握手。

## 从零理解协议

**IP** 是网络地址。`127.0.0.1` 是本机回环地址，连接不会发送到校园网或第三方服务器；端口用于区分同一台机器上的服务。

**TCP stream** 是 TCP 给应用提供的连续、有序字节流，不是“一包对应一次 recv”。应用必须自己判断消息边界。

```text
send() != TCP packet
recv() != TCP packet
```

一次 send 可能分成多次 recv，多次 send 也可能由一次 recv 读出。第一版实验人为定义 Segment，目的是确定性演示“跨数据块 Parser 状态”问题；真实 TCP 的 packetization/recv boundaries 由网络栈决定，并不保证与 send() 一一对应。本实验的教学 Segment 是应用层帧，不能当作真实 TCP segment；没有 raw socket、构包或抓包驱动。

**TLS** 用于保护通信，HTTPS 通常使用 TLS。**ClientHello** 是 TLS 握手最开始由客户端发送的数据之一，携带协商参数和扩展。这里通过 `ssl.MemoryBIO`、`SSLContext.wrap_bio()` 和 `do_handshake()` 在内存里生成它，遇到等待服务端数据的 `SSLWantReadError` 后读取 outgoing BIO；不需要证书，也不建立外网连接。

**SNI** 表示客户端想连接的 hostname，位于 `server_name` 扩展中（类型 0）。它与连接使用的 IP 地址不同。本实验生成器只接受 `.test` 域名，不进行 DNS 查询。协议结构参考 [RFC 6066 第 3 节](https://www.rfc-editor.org/rfc/rfc6066.html#section-3) 与 [RFC 8446 ClientHello](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1.2)。

**Parser** 是把二进制数据解释成 TLS、ClientHello、扩展和 SNI 等结构的程序。**Parser Differential** 是不同解析器对同一逻辑数据有不同理解：`Firewall View != Server View`。

## 为什么简单防火墙会失败

该防火墙故意模拟“只检查当前数据块、不执行跨块重组”的错误实现。

```text
Segment 1: blocked.  → Naive 不匹配 → 转发
Segment 2: test      → Naive 不匹配 → 转发

Server: blocked. + test = blocked.test
```

完整的 `blocked.test` 在一个 Segment 中出现则被 Naive 阻断。改进版本先缓存，直到完成标记，再检查拼接后的数据，所以跨 Segment 也会阻断。

| 场景 | Naive | Reassembly | Naive 链路 Server |
|---|---|---|---|
| allowed.test | PASS | PASS | allowed.test |
| blocked.test | BLOCK | BLOCK | 无完整消息 |
| blocked. + test | PASS | BLOCK | blocked.test |
| blo + cked + .test | PASS | BLOCK | blocked.test |
| allo + wed. + test | PASS | PASS | allowed.test |
| TLS SNI 完整 | BLOCK | BLOCK | 无完整消息 |
| TLS SNI 跨块 | MISSED（PASS） | BLOCK | 原始 ClientHello 字节 |

TLS 演示在真实 ClientHello 的 `blocked.` 后切开。每块单独解析都无法获得完整 SNI，拼接后得到 `blocked.test`。单元测试也覆盖同一握手跨多个 TLS record 的情况，TLS record 边界与教学 Segment 边界是不同层次。

## 消息完成与错误处理

每帧是 `4 字节无符号大端长度 + payload`；长度为 0 的帧专门表示消息结束，不能表示普通空 Segment。每连接只处理一条消息。`read_frame()` 循环读取头部和 payload，正确处理 partial recv。

单帧与累计消息均限制为 1 MiB，最多 4096 个非空 Segment；每次阻塞 socket 操作超时为 5 秒（不是整条消息的绝对期限）。超大长度、提前 EOF、截断帧会拒绝。负长度不能用此无符号字段表示。收到显式结束标记前关闭连接不会产生 SERVER_OK。

Naive 可能已转发前缀后才遇到黑名单；Server 可记录这些片段，但不会把前缀作为完成消息。重组版在判定 PASS 前不连接后端。重组缓存受限，但本项目采用串行教学服务，不是抗并发攻击的生产代理。

`extract_sni()` 对所有嵌套长度检查边界；不完整、格式非法、不支持的结构、无 SNI 统一返回 `None`。它只接受一个 ClientHello，可跨连续的明文 handshake records；拒绝尾随数据、重复扩展与重复名称。最大输入 1 MiB，单 record 最大 16384 字节。它不是完整 TLS 校验器，不处理后续握手或加密记录。

Naive TLS 模式故意把 `None` 当作没有命中而放行。重组 TLS 模式对 `None` 采取拒绝策略，防止把解析失败等同允许。对成功解析的 SNI 使用小写精确匹配 `blocked.test`，文本模式则按大小写敏感的字节子串匹配。这些是明确简化的教学策略。

## 正确防御与实际限制

```text
接收数据 → 维护连接状态 → 限额缓存 → 重组 stream
         → 解析完整协议结构 → 执行策略 → 转发
```

真实 DPI 还需要处理资源耗尽、超时、协议状态、重叠策略、加密和复杂应用行为，远比本实验复杂。本项目只证明本地模拟解析器存在不同视图，不能据此推断任何真实网络设备的行为。

## Sequence number 教学

`lab/sequence.py` 使用内存中的 `Segment(seq, payload)`，seq 是从零开始的字节偏移，不是 TCP 头部字段，不模拟 TCP 序号回绕、ACK、重传计时或 FIN 消耗序号。

```text
收到 seq=6 GHI，seq=0 ABC，seq=3 DEF → ABCDEFGHI
收到 seq=0 ABC，seq=6 GHI → GAP DETECTED，expected 3，actual 6
只收到 seq=0 ABC → 连续，但 END UNKNOWN
```

相同重复字节被接受，冲突重叠报错；传入 `expected_length` 才能报告 COMPLETE 或已知尾部缺口。单纯看到目前的数据连续，并不意味着发送方已经没有更多数据要发送。结束条件来自 FIN、应用层长度、协议 framing、connection close 或其他协议状态；其中 close 也可能代表失败，必须结合应用协议判断。本实验使用明确的结束帧。

## 验证与范围

测试覆盖基础 framing、EOF/长度/数量限制、五组本机链路对照、已转发前缀后的阻断、真实 ClientHello、所有前缀截断、畸形嵌套长度、重复扩展、随机输入、TLS record 分段、TLS 本机链路与 sequence 场景。演示还对服务端完整字节流进行断言。

仅绑定和连接 `127.0.0.1`；没有修改 Windows Defender Firewall、DNS、路由、代理或注册表；没有安装 WinDivert、Npcap、Scapy 或规避工具，没有第三方实验流量。可离线运行全部测试与演示。
