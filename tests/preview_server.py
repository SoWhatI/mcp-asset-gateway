"""仅用于本地浏览器验收：临时数据库、随机密码、禁止真实出站连接。"""

import secrets
import tempfile
from pathlib import Path

import uvicorn
from cryptography.fernet import Fernet

from app.core.config import Config
from app.core.security import GatewayError
from app.main import create_app


def preview_app():
    folder = Path(__file__).resolve().parent.parent / ".preview"
    folder.mkdir(mode=0o700, exist_ok=True)
    data = Path(tempfile.mkdtemp(dir=folder))
    config = Config(
        str(data / "data/gateway.db"),
        Fernet.generate_key().decode(),
        "preview-only",
        "http://localhost:8303",
        False,
        ("localhost", "127.0.0.1"),
        ("http://localhost:8303",),
        ({"host": "db.example.test", "port": 3306},),
    )
    app = create_app(config)
    gateway = app.state.gateway
    gateway.store.acquire()
    try:
        gateway.store.migrate()
        password = secrets.token_urlsafe(18)
        gateway.manager.init_admin("preview", password)
    finally:
        gateway.store.release()

    def no_outbound(*args):
        raise GatewayError("PREVIEW_ONLY", "预览环境禁止真实出站连接", 403)

    gateway.network.resolve = no_outbound
    print("本地临时验收账号：preview；密码：" + password, flush=True)
    print("数据库：" + str(data) + "；重启后使用新的临时数据和密码。", flush=True)
    return app


if __name__ == "__main__":
    uvicorn.run(preview_app(), host="127.0.0.1", port=8303, access_log=False)
