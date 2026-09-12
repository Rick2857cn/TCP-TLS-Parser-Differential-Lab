# 验收记录

2026-09-07 本机执行：

| 命令 | 结果 |
|---|---|
| `.\scripts\run_demo.ps1` | Python 3.14，21 tests，OK；演示所有断言通过 |
| `python -m unittest discover -v` | Python 3.10.11，21 tests，OK |

完整脚本输出见 `demo-results.txt`，默认 Python 测试输出见 `test-results-python310.txt`，早期 TLS 阶段输出见 `tls-test-results.txt`。日志由 Windows PowerShell 重定向保存。

实测：allowed 双方 PASS；blocked 完整输入双方 BLOCK；blocked. + test 为 Naive PASS / Reassembly BLOCK，Naive 后端完整收到 blocked.test；TLS 完整 SNI 双方 BLOCK，拆分 SNI 为 Naive MISSED / Reassembly BLOCK。

已检查网络调用：全部地址使用固定 HOST = 127.0.0.1。演示上下文关闭 listener、连接并等待线程退出。无软件安装和系统设置修改。

## IP 或 SNI 组合策略扩展

2026-09-11 增加最坏情况策略：模拟目标 IP `192.0.2.10` 或 SNI `blocked.test` 任一命中即阻断。`192.0.2.20` 作为允许对照；这些地址只进入内存策略判断，不用于 socket 连接。

验收条件：四象限真值表全部通过；拆分 `blocked.test` 在允许 IP 下仍呈现 Naive MISSED / Reassembly BLOCK，在黑名单 IP 下两者均 BLOCK，后端未收到消息。Python 3.14 与 Python 3.10 均通过全量 22 项测试。

## 双重解析差分扩展

2026-09-11 增加 `::ffff:192.0.2.10` 与拆分 SNI 的组合场景。Naive 未规范化映射地址且未重组 SNI，因此返回 PASS，后端收到完整 ClientHello；改进版将地址规范化为黑名单 IPv4 后返回 BLOCK。全量测试增加至 23 项。
