"""容器健康检查：HTTP 服务模式探测 /ready；stdio 自举模式视为健康。"""

import os
import sys
import urllib.request

if os.getenv("GATEWAY_MASTER_KEY"):
    urllib.request.urlopen("http://127.0.0.1:8303/ready", timeout=3)
sys.exit(0)
