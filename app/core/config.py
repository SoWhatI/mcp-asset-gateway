import json
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

DEFAULTS = {
    "query_timeout_seconds": 30,
    "connect_timeout_seconds": 5,
    "max_result_rows": 500,
    "max_output_bytes": 524288,
    "max_cell_chars": 1000,
    "audit_retention_days": 90,
}
LIMITS = {
    "query_timeout_seconds": (1, 30),
    "connect_timeout_seconds": (1, 10),
    "max_result_rows": (1, 5000),
    "max_output_bytes": (1024, 1048576),
    "max_cell_chars": (1, 10000),
    "audit_retention_days": (1, 3650),
}


@dataclass(frozen=True)
class Config:
    database: str
    master_key: str
    key_id: str
    public_url: str
    secure_cookie: bool
    hosts: tuple[str, ...]
    origins: tuple[str, ...]
    outbound: tuple[dict, ...]
    legacy: bool = False
    ssh_host_key_enforce: bool = False

    @property
    def outbound_enforce(self):
        """登记列表非空时启用强制登记校验；null/空列表表示不开启。"""
        return bool(self.outbound)

    @classmethod
    def from_env(cls):
        url = os.getenv("PUBLIC_BASE_URL", "http://localhost:8303").rstrip("/")
        parsed = urlsplit(url)
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("PUBLIC_BASE_URL 必须为无路径和凭据的 HTTP(S) 地址")
        key = os.getenv("GATEWAY_MASTER_KEY", "")
        if not key:
            raise ValueError("必须配置 GATEWAY_MASTER_KEY；可先运行 python -m app.cli setup")
        hosts = tuple(
            x.strip().lower()
            for x in os.getenv("ALLOWED_HOSTS", f"{parsed.hostname},127.0.0.1").split(",")
            if x.strip()
        )
        origins = tuple(x.strip() for x in os.getenv("ALLOWED_ORIGINS", url).split(",") if x.strip())
        if "*" in hosts or "*" in origins:
            raise ValueError("不允许通配 Host 或 Origin")
        raw = os.getenv("OUTBOUND_ALLOWLIST", "null").strip()
        if raw.lower() in ("", "null", "none"):
            outbound = []
        else:
            try:
                outbound = json.loads(raw)
            except ValueError:
                raise ValueError(
                    'OUTBOUND_ALLOWLIST 必须为 JSON 数组或 null，如 [{"host":"目标主机","port":端口}]'
                ) from None
        if outbound is None:
            outbound = []
        if not isinstance(outbound, list) or any(
            not isinstance(x, dict)
            or not isinstance(x.get("host"), str)
            or not x["host"].strip()
            or type(x.get("port")) is not int
            or not 1 <= x["port"] <= 65535
            or ("allow_http" in x and type(x["allow_http"]) is not bool)
            for x in outbound
        ):
            raise ValueError('OUTBOUND_ALLOWLIST 必须为 [{"host":"目标主机","port":端口}] 或 null')
        return cls(
            database=os.getenv("DATABASE_PATH", "data/gateway.db"),
            master_key=key,
            key_id=os.getenv("GATEWAY_MASTER_KEY_ID", "key-1"),
            public_url=url,
            secure_cookie=os.getenv("COOKIE_SECURE", "true").lower() == "true",
            hosts=hosts,
            origins=origins,
            outbound=tuple(outbound),
            legacy=os.getenv("LEGACY_COMPAT", "false").lower() == "true",
            ssh_host_key_enforce=os.getenv("SSH_HOST_KEY_ENFORCE", "false").lower() == "true",
        )

    @property
    def data_dir(self):
        return Path(self.database).resolve().parent
