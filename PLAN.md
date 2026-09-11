# 实施计划

按顺序实现并测试：framing → Server/Naive/Client → 重组 → TLS → sequence → 一键演示与文档 → 全量验收。

仅使用标准库；监听、连接地址固定为 127.0.0.1。零长度帧是消息结束标记；EOF 不是消息成功结束。每连接一条消息，超时 5 秒，消息上限 1 MiB，最多 4096 个 Segment。

## 完成记录

- 基础阶段：6 项测试通过。
- 重组阶段：8 项累计测试通过，含五组真实 loopback 对照。
- TLS 阶段：7 项 TLS 测试通过。
- Sequence 阶段：4 项测试通过。
- 补充嵌套长度与 Segment 数量边界测试后：全量 21 项测试通过。
- PowerShell 一键脚本通过，Python 3.14 与 Python 3.10 均通过全量测试。
- 中文 README、环境记录与验收日志已完成。
