import os
import uuid

from app.core.db import dumps, now
from app.core.manager import audit
from app.core.security import GatewayError, digest


def import_legacy(gateway):
    store, vault = gateway.store, gateway.vault
    with store.connect(write=True) as conn:
        if store.settings(conn).get("legacy_import_completed"):
            return
        required = ("AGENT_TOKEN", "DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD")
        if any(not os.getenv(key) for key in required):
            raise GatewayError("LEGACY_INCOMPLETE", "legacy 导入配置不完整", 503)
        mode = os.getenv("SSL_MODE", "VERIFY_IDENTITY")
        if mode not in ("PREFERRED", "VERIFY_IDENTITY", "REQUIRED", "DISABLED"):
            raise GatewayError("LEGACY_TLS", "legacy TLS 模式不受支持", 503)
        connection = {"host": os.environ["DB_HOST"], "port": int(os.getenv("DB_PORT", "3306")), "tls_mode": mode}
        gateway.manager.validate_asset({"type": "mysql", "connection": connection})
        stamp, token = now(), os.environ["AGENT_TOKEN"]
        if any(
            conn.execute(f"SELECT 1 FROM {table} WHERE id=?", (identity,)).fetchone()
            for table, identity in (("assets", "legacy-mysql"), ("accounts", "legacy-ro"), ("clients", "legacy-client"))
        ):
            raise GatewayError("LEGACY_CONFLICT", "旧版对象已存在，导入已回滚", 409)
        conn.execute(
            "INSERT INTO assets(id,name,type,connection_json,created_at,updated_at) VALUES(?,?,?,?,?,?)",
            ("legacy-mysql", "旧 MySQL 服务", "mysql", dumps(connection), stamp, stamp),
        )
        conn.execute(
            "INSERT INTO accounts(id,asset_id,name,config_json,credential_ciphertext,credential_key_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
            (
                "legacy-ro",
                "legacy-mysql",
                "旧只读账号",
                dumps({"username": os.environ["DB_USER"], "database": os.environ["DB_NAME"]}),
                vault.encrypt({"password": os.environ["DB_PASSWORD"]}),
                vault.key_id,
                stamp,
                stamp,
            ),
        )
        conn.execute(
            "INSERT INTO clients(id,name,token_hash,token_tail,compatibility_mode,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            ("legacy-client", "旧业务客户端", digest(token), token[-4:], "legacy_mysql", stamp, stamp),
        )
        grant_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO grants(id,name,tools_json,created_at,updated_at) VALUES(?,?,?,?,?)",
            (
                grant_id,
                "旧 MySQL 授权组",
                dumps(["list_tables", "describe_table", "execute_query"]),
                stamp,
                stamp,
            ),
        )
        conn.execute("INSERT INTO grant_clients(grant_id,client_id) VALUES(?,?)", (grant_id, "legacy-client"))
        conn.execute(
            "INSERT INTO grant_accounts(grant_id,account_id,tools_json) VALUES(?,?,?)",
            (grant_id, "legacy-ro", dumps(["list_tables", "describe_table", "execute_query"])),
        )
        conn.execute(
            "INSERT INTO settings(key,value_json,updated_at) VALUES('legacy_import_completed','true',?)", (stamp,)
        )
        audit(conn, "legacy.import", source="system")
