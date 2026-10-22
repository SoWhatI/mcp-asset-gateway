"""插件运行时：SDK、工作进程、进程管理与主进程桥接。

目录约定：
- sdk/      纯标准库的插件 SDK（安装时拷贝到插件目录，插件作者 import mag_plugin）
- worker.py 纯标准库的工作进程入口（由插件 venv 解释器运行，不依赖网关代码）
- process.py 主进程侧进程池管理
- bridge.py 插件类型到 AssetType 接口的桥接适配器
"""
