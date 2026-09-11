# 验收记录

2026-09-07 本机执行：

| 命令 | 结果 |
|---|---|
| `.\scripts\run_demo.ps1` | Python 3.14，21 tests，OK；演示所有断言通过 |
| `python -m unittest discover -v` | Python 3.10.11，21 tests，OK |

完整脚本输出见 `demo-results.txt`，默认 Python 测试输出见 `test-results-python310.txt`，早期 TLS 阶段输出见 `tls-test-results.txt`。日志由 Windows PowerShell 重定向保存。

实测：allowed 双方 PASS；blocked 完整输入双方 BLOCK；blocked. + test 为 Naive PASS / Reassembly BLOCK，Naive 后端完整收到 blocked.test；TLS 完整 SNI 双方 BLOCK，拆分 SNI 为 Naive MISSED / Reassembly BLOCK。

已检查网络调用：全部地址使用固定 HOST = 127.0.0.1。演示上下文关闭 listener、连接并等待线程退出。无软件安装和系统设置修改。
