# 环境检测

2026-09-07，Windows PowerShell：

- `python --version`: Python 3.10.11
- `py --version`: Python 3.14.0（项目优先使用）
- `where.exe python`: Python310/python.exe 与 WindowsApps/python.exe
- `wsl --status`: 默认发行版 docker-desktop，默认版本 2
- `wsl -l -v`: docker-desktop，Running，版本 2（命令输出含 UTF-16 空字符）

未安装软件、未修改系统设置。既有原生 Python 可用，不使用 WSL。
