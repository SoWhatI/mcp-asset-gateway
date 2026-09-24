import datetime
import json
import re
import secrets
import uuid

from app.core.config import DEFAULTS, LIMITS
from app.core.db import decode, dumps, now
from app.core.security import GatewayError, digest, equal, new_token, password_check, password_hash, validate
from app.core.tool_rules import validate_rules

TABLES = {"assets", "accounts", "clients", "grants"}
ID_PATTERN = r"^[a-z][a-z0-9-]{0,23}$"
ID_PREFIX = {"assets": "asset", "accounts": "acct", "clients": "cli"}


def new_identity(table):
    return f"{ID_PREFIX[table]}-{secrets.token_hex(6)}"


def public(value):
    value = dict(value)
    if "credential_ciphertext" in value:
        value["credential_present"] = bool(value.pop("credential_ciphertext"))
    for key in ("token_hash", "password_hash", "credential_key_id", "tool_catalog"):
        value.pop(key, None)
    return value


def fetch(conn, table, identity):
    if table not in TABLES:
        raise GatewayError("NOT_FOUND", "对象不存在", 404)
    if not isinstance(identity, str) or not identity or len(identity) > 64:
        raise GatewayError("VALIDATION", "请选择有效对象并重试")
    value = decode(conn.execute(f"SELECT * FROM {table} WHERE id=?", (identity,)).fetchone())
    if value is None:
        raise GatewayError("NOT_FOUND", "对象不存在", 404)
    return value


def with_targets(conn, grant):
    grant["client_ids"] = [
        row[0]
        for row in conn.execute(
            "SELECT client_id FROM grant_clients WHERE grant_id=? ORDER BY client_id", (grant["id"],)
        )
    ]
    grant["entries"] = [
        grant_entry(row[0], row[1], row[2])
        for row in conn.execute(
            "SELECT account_id,tools_json,parameter_rules_json FROM grant_accounts WHERE grant_id=? ORDER BY account_id",
            (grant["id"],),
        )
    ]
    # 派生只读字段：兼容旧调用方展示账号列表与工具并集。
    grant["account_ids"] = [entry["account_id"] for entry in grant["entries"]]
    grant["tools"] = sorted({tool for entry in grant["entries"] for tool in entry["tools"]})
    return grant


def grant_entry(account_id, tools, rules):
    entry = {"account_id": account_id, "tools": json.loads(tools)}
    if rules != "{}":
        entry["parameter_rules"] = json.loads(rules)
    return entry


def grant_entries(raw):
    """校验并归一化“资产账号-工具”条目列表。"""
    if (
        not isinstance(raw, list)
        or len(raw) > 50
        or any(
            not isinstance(entry, dict)
            or set(entry) - {"account_id", "tools", "parameter_rules"}
            or not isinstance(entry.get("account_id"), str)
            or not isinstance(entry.get("tools", []), list)
            or any(not isinstance(tool, str) for tool in entry.get("tools", []))
            or len(entry.get("tools", [])) > 200
            or len(set(entry.get("tools", []))) != len(entry.get("tools", []))
            for entry in raw
        )
    ):
        raise GatewayError("VALIDATION", "资产账号条目格式不正确：每组最多 50 个账号，工具需为不重复的显式名称数组")
    if len({entry["account_id"] for entry in raw}) != len(raw):
        raise GatewayError("VALIDATION", "同一资产账号在组内只能有一条配置，请合并后重试")
    return [
        {
            "account_id": entry["account_id"],
            "tools": list(entry.get("tools", [])),
            "parameter_rules": validate_rules(entry.get("parameter_rules", {}), entry.get("tools", [])),
        }
        for entry in raw
    ]


def audit(conn, event, actor=None, source="ui", status="ok", request_id=None, **fields):
    stamp = now()
    values = {
        "request_id": request_id or str(uuid.uuid4()),
        "ts": stamp,
        "completed_at": None if status == "started" else stamp,
        "event": event,
        "source": source,
        "status": status,
        "actor_type": "client" if source == "mcp" else "admin" if source == "ui" else "system",
        "actor_id": actor,
    }
    allowed = {
        "client_id",
        "asset_id",
        "account_id",
        "tool",
        "token_tail",
        "error_code",
        "elapsed_ms",
        "snapshot_json",
        "detail_json",
        "row_count",
        "output_bytes",
        "truncated",
    }
    values.update({k: v for k, v in fields.items() if k in allowed})
    conn.execute(
        f"INSERT INTO audit_log({','.join(values)}) VALUES({','.join('?' for _ in values)})", tuple(values.values())
    )
    return values["request_id"]


class Manager:
    def __init__(self, store, vault, registry, network):
        self.store, self.vault, self.registry, self.network = store, vault, registry, network
        self.dummy_hash = password_hash(secrets.token_urlsafe(24))

    def check_all_credentials(self):
        with self.store.connect() as conn:
            for row in conn.execute("SELECT credential_ciphertext,credential_key_id FROM accounts"):
                self.vault.decrypt(row[0], row[1])

    def init_admin(self, username, password):
        if not re.fullmatch(r"[A-Za-z0-9_-]{3,40}", username):
            raise GatewayError("USERNAME", "用户名须为 3～40 位字母、数字、下划线或连字符")
        hashed, identity = password_hash(password), str(uuid.uuid4())
        with self.store.connect(write=True) as conn:
            if conn.execute("SELECT 1 FROM admin_users").fetchone():
                raise GatewayError("ADMIN_EXISTS", "管理员已初始化；请使用改密流程", 409)
            conn.execute(
                "INSERT INTO admin_users(id,username,password_hash,created_at,updated_at) VALUES(?,?,?,?,?)",
                (identity, username, hashed, now(), now()),
            )
            audit(conn, "admin.initialize", source="system")
        return identity

    def login(self, username, password):
        with self.store.connect() as conn:
            row = conn.execute("SELECT * FROM admin_users WHERE username=? AND enabled=1", (username,)).fetchone()
        valid = password_check(password, row["password_hash"] if row else self.dummy_hash)
        if not row or not valid:
            with self.store.connect(write=True) as conn:
                audit(conn, "auth.login", status="denied", error_code="INVALID_CREDENTIALS")
            raise GatewayError("INVALID_CREDENTIALS", "用户名或密码错误", 401)
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.store.connect(write=True) as conn:
            current = conn.execute("SELECT * FROM admin_users WHERE id=? AND enabled=1", (row["id"],)).fetchone()
            if not current or current["password_hash"] != row["password_hash"]:
                raise GatewayError("INVALID_CREDENTIALS", "用户名或密码错误", 401)
            conn.execute(
                "INSERT INTO admin_sessions VALUES(?,?,?,?,?,?,?,NULL)",
                (str(uuid.uuid4()), row["id"], digest(token), digest(csrf), now(), now(), now() + 28800000),
            )
            audit(conn, "auth.login", row["id"])
        return {"id": row["id"], "username": row["username"]}, token, csrf

    def session(self, token, csrf=None):
        if not token:
            raise GatewayError("UNAUTHENTICATED", "请先登录", 401)
        with self.store.connect(write=True) as conn:
            row = conn.execute(
                "SELECT s.*,u.username,u.enabled FROM admin_sessions s JOIN admin_users u ON s.admin_id=u.id "
                "WHERE s.session_hash=?",
                (digest(token),),
            ).fetchone()
            if (
                not row
                or not row["enabled"]
                or row["revoked_at"]
                or row["expires_at"] <= now()
                or row["last_seen_at"] < now() - 1800000
            ):
                raise GatewayError("UNAUTHENTICATED", "会话已失效，请重新登录", 401)
            if csrf is not None and not equal(digest(csrf), row["csrf_hash"]):
                raise GatewayError("CSRF", "CSRF 校验失败", 403)
            if row["last_seen_at"] < now() - 60000:
                conn.execute("UPDATE admin_sessions SET last_seen_at=? WHERE id=?", (now(), row["id"]))
            return {"id": row["admin_id"], "username": row["username"], "session_id": row["id"]}

    def logout(self, actor):
        with self.store.connect(write=True) as conn:
            conn.execute("UPDATE admin_sessions SET revoked_at=? WHERE id=?", (now(), actor["session_id"]))
            audit(conn, "auth.logout", actor["id"])

    def change_password(self, actor, old, new):
        hashed = password_hash(new)
        with self.store.connect() as conn:
            row = conn.execute("SELECT password_hash FROM admin_users WHERE id=?", (actor["id"],)).fetchone()
        if not row or not password_check(old, row[0]):
            raise GatewayError("INVALID_CREDENTIALS", "原密码不正确", 403)
        with self.store.connect(write=True) as conn:
            changed = conn.execute(
                "UPDATE admin_users SET password_hash=?,updated_at=? WHERE id=? AND password_hash=?",
                (hashed, now(), actor["id"], row[0]),
            ).rowcount
            if not changed:
                raise GatewayError("CONFLICT", "密码已变更，请重新登录", 409)
            conn.execute("UPDATE admin_sessions SET revoked_at=? WHERE admin_id=?", (now(), actor["id"]))
            audit(conn, "auth.password", actor["id"])

    def client(self, identity=None, token=None, conn=None):
        if (token is not None and not isinstance(token, str)) or (token is None and not isinstance(identity, str)):
            raise GatewayError("UNAUTHORIZED", "客户端身份格式无效", 401)
        if conn is None:
            with self.store.connect() as current:
                return self.client(identity, token, current)
        row = conn.execute(
            "SELECT * FROM clients WHERE " + ("token_hash=?" if token is not None else "id=?"),
            (digest(token) if token is not None else identity,),
        ).fetchone()
        if not row or not row["enabled"] or (row["token_expires_at"] and row["token_expires_at"] <= now()):
            raise GatewayError("UNAUTHORIZED", "客户端身份无效或已过期", 401)
        return decode(row)

    def list(self, table, limit=20, offset=0):
        if table not in TABLES:
            raise GatewayError("NOT_FOUND", "对象不存在", 404)
        limit = max(1, min(100, limit))
        offset = max(0, offset)
        with self.store.connect() as conn:
            rows = [
                decode(row)
                for row in conn.execute(
                    f"SELECT * FROM {table} ORDER BY created_at DESC,id LIMIT ? OFFSET ?", (limit, offset)
                ).fetchall()
            ]
            total = conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            if table == "grants" and rows:
                marks = {row["id"]: row for row in rows}
                for row in rows:
                    row["client_ids"], row["account_ids"], row["entries"] = [], [], []
                placeholders = ",".join("?" for _ in rows)
                for target in conn.execute(
                    f"SELECT grant_id,client_id FROM grant_clients WHERE grant_id IN ({placeholders}) "
                    "ORDER BY grant_id,client_id",
                    tuple(marks),
                ):
                    marks[target["grant_id"]]["client_ids"].append(target["client_id"])
                for target in conn.execute(
                    f"SELECT grant_id,account_id,tools_json,parameter_rules_json FROM grant_accounts WHERE grant_id IN ({placeholders}) "
                    "ORDER BY grant_id,account_id",
                    tuple(marks),
                ):
                    marks[target["grant_id"]]["entries"].append(
                        grant_entry(target["account_id"], target["tools_json"], target["parameter_rules_json"])
                    )
                for row in rows:
                    row["account_ids"] = [entry["account_id"] for entry in row["entries"]]
                    row["tools"] = sorted({tool for entry in row["entries"] for tool in entry["tools"]})
        return {
            "items": [public(row) for row in rows],
            "total": total,
            "next_cursor": offset + limit if offset + limit < total else None,
        }

    def get(self, table, identity):
        with self.store.connect() as conn:
            value = fetch(conn, table, identity)
            if table == "grants":
                with_targets(conn, value)
            return public(value)

    def validate_asset(self, value):
        if not isinstance(value.get("type"), str):
            raise GatewayError("ASSET_TYPE", "资产类型必须为字符串")
        kind = self.registry.get(value.get("type"))
        if not kind:
            raise GatewayError("ASSET_TYPE", "资产类型不存在")
        validate(kind.connection_schema, value.get("connection"))
        kind.validate_connection(self.network, value["connection"])

    def save(self, table, body, actor, identity=None):
        if table not in TABLES or not isinstance(body, dict):
            raise GatewayError("VALIDATION", "对象类型或数据格式不合法")
        allowed = {
            "assets": {"id", "name", "type", "connection", "enabled", "revision"},
            "accounts": {"id", "name", "asset_id", "config", "credential", "policy", "note", "enabled", "revision"},
            "clients": {"id", "name", "token_expires_at", "enabled", "revision"},
            "grants": {"name", "client_ids", "entries", "account_ids", "tools", "tool_versions", "enabled", "revision"},
        }[table]
        if set(body) - allowed:
            raise GatewayError("VALIDATION", "包含不支持的字段")
        returned_token = None
        with self.store.connect(write=True) as conn:
            old = fetch(conn, table, identity) if identity else None
            if old and table == "grants":
                with_targets(conn, old)
            if old and (type(body.get("revision")) is not int or body["revision"] != old["revision"]):
                raise GatewayError("CONFLICT", "记录已被修改，请刷新后重试", 409)
            value = {**(old or {}), **body}
            if identity or body.get("id"):
                value["id"] = identity or body["id"]
            elif table == "grants":
                value["id"] = str(uuid.uuid4())
            else:
                value["id"] = new_identity(table)
            if not isinstance(value["id"], str) or len(value["id"]) > 64:
                raise GatewayError("ID_INVALID", "对象信息格式不正确，请刷新后重试")
            if table != "grants" and not re.fullmatch(ID_PATTERN, value["id"]):
                raise GatewayError("ID_INVALID", "对象信息格式不正确，请刷新后重试")
            reserved = self.store.settings(conn).get("reserved_ids", [])
            if not old and value["id"] in reserved:
                raise GatewayError("ID_RESERVED", "该对象信息已被使用，请重新创建", 409)
            if old and body.get("id", identity) != identity:
                raise GatewayError("IMMUTABLE", "不能更换正在编辑的对象，请刷新后重试")
            enabled = value.get("enabled", True)
            if type(enabled) not in (bool, int) or enabled not in (0, 1):
                raise GatewayError("VALIDATION", "enabled 必须为布尔值")
            record = {"id": value["id"], "enabled": int(enabled), "updated_at": now()}
            if table == "grants":
                value.setdefault("name", "未命名授权组")
            if not isinstance(value.get("name"), str) or not 1 <= len(value["name"].strip()) <= 100:
                raise GatewayError("VALIDATION", "名称长度必须为 1～100 个字符")
            record["name"] = value["name"].strip()
            if table == "assets":
                if old and value["type"] != old["type"]:
                    raise GatewayError("IMMUTABLE", "资产类型不可修改")
                self.validate_asset(value)
                record.update(type=value["type"], connection_json=dumps(value["connection"]))
                if old and value["connection"] != old["connection"]:
                    # 地址变更后，旧批准不能悄悄用于另一台上游服务器。
                    conn.execute(
                        "UPDATE accounts SET tool_catalog_json='[]',catalog_refreshed_at=NULL,revision=revision+1 WHERE asset_id=?",
                        (identity,),
                    )
                    for account_row in conn.execute("SELECT id FROM accounts WHERE asset_id=?", (identity,)):
                        conn.execute(
                            "UPDATE grants SET tool_versions_json=json_remove(tool_versions_json,'$.'||?),"
                            "revision=revision+1 WHERE id IN (SELECT grant_id FROM grant_accounts WHERE account_id=?)",
                            (account_row["id"], account_row["id"]),
                        )
            elif table == "accounts":
                asset = fetch(conn, "assets", value.get("asset_id"))
                if old and value["asset_id"] != old["asset_id"]:
                    raise GatewayError("IMMUTABLE", "账号不可换绑资产")
                credential = (
                    body.get("credential")
                    if "credential" in body
                    else (self.vault.decrypt(old["credential_ciphertext"], old["credential_key_id"]) if old else {})
                )
                if not isinstance(credential, dict):
                    raise GatewayError("VALIDATION", "credential 必须为完整凭据对象")
                config, policy = value.get("config", {}), value.get("policy", {})
                self.registry[asset["type"]].validate_config(asset["connection"], config, policy, credential)
                if not isinstance(value.get("note", ""), str) or len(value.get("note", "")) > 500:
                    raise GatewayError("VALIDATION", "账号说明最长 500 字符")
                record.update(
                    asset_id=asset["id"],
                    config_json=dumps(config),
                    policy_json=dumps(policy),
                    credential_ciphertext=self.vault.encrypt(credential) if credential else None,
                    credential_key_id=self.vault.key_id if credential else None,
                    note=value.get("note", ""),
                )
                if not old or "credential" in body or config != old["config"]:
                    record.update(tool_catalog_json="[]", catalog_refreshed_at=None)
                    if old:
                        conn.execute(
                            "UPDATE grants SET tool_versions_json=json_remove(tool_versions_json,'$.'||?),"
                            "revision=revision+1 WHERE id IN (SELECT grant_id FROM grant_accounts WHERE account_id=?)",
                            (identity, identity),
                        )
            elif table == "clients":
                expires = value.get("token_expires_at")
                if expires is not None and (type(expires) is not int or not now() < expires <= 253402300799999):
                    raise GatewayError("VALIDATION", "有效期必须为未来时间或 null")
                record["token_expires_at"] = expires
                if not old:
                    returned_token = new_token()
                    record.update(token_hash=digest(returned_token), token_tail=returned_token[-4:])
            else:
                client_ids = value.get("client_ids", [])
                if (
                    not isinstance(client_ids, list)
                    or len(client_ids) > 50
                    or any(not isinstance(one, str) for one in client_ids)
                    or len(set(client_ids)) != len(client_ids)
                ):
                    raise GatewayError("VALIDATION", "客户端选择格式不正确，最多选择 50 个且不能重复")
                if "entries" in body:
                    raw_entries = body["entries"]
                elif "account_ids" in body or "tools" in body:
                    # 兼容旧平铺格式：同一份工具白名单应用到每个账号成员。
                    legacy_accounts, legacy_tools = value.get("account_ids", []), value.get("tools", [])
                    if (
                        not isinstance(legacy_accounts, list)
                        or len(legacy_accounts) > 50
                        or any(not isinstance(one, str) for one in legacy_accounts)
                        or len(set(legacy_accounts)) != len(legacy_accounts)
                        or not isinstance(legacy_tools, list)
                        or any(not isinstance(tool, str) for tool in legacy_tools)
                        or len(legacy_tools) > 200
                        or len(set(legacy_tools)) != len(legacy_tools)
                    ):
                        raise GatewayError("VALIDATION", "资产账号或工具选择格式不正确，请刷新后重试")
                    raw_entries = [
                        {"account_id": account_id, "tools": list(legacy_tools)} for account_id in legacy_accounts
                    ]
                else:
                    raw_entries = value.get("entries", [])
                entries = grant_entries(raw_entries)
                # 旧客户端未传规则时保留原规则；只有显式传 {} 才表示清空。
                previous = {entry["account_id"]: entry for entry in (old or {}).get("entries", [])}
                for entry, raw in zip(entries, raw_entries, strict=True):
                    if "parameter_rules" not in raw:
                        entry["parameter_rules"] = {
                            name: rules
                            for name, rules in previous.get(entry["account_id"], {}).get("parameter_rules", {}).items()
                            if name in entry["tools"]
                        }
                for client_id in client_ids:
                    fetch(conn, "clients", client_id)
                accounts = {entry["account_id"]: fetch(conn, "accounts", entry["account_id"]) for entry in entries}
                revoking = old is not None and set(body) <= {"revision", "name", "enabled"} and not enabled
                metadata_only = old is not None and set(body) <= {"revision", "name"}
                revoking = revoking or metadata_only
                versions = old["tool_versions"] if revoking else {}
                if any(entry["tools"] for entry in entries) and not revoking:
                    for entry in entries:
                        if not entry["tools"]:
                            continue
                        account = accounts[entry["account_id"]]
                        asset = fetch(conn, "assets", account["asset_id"])
                        specs = self.registry[asset["type"]].catalog(account)
                        catalog = {item["name"]: item for item in specs}
                        if set(entry["tools"]) - set(catalog):
                            raise GatewayError(
                                "TOOL_INVALID", f"部分工具不在账号 {account['name']} 的目录中，请重新选择或刷新目录"
                            )
                        validate_rules(entry["parameter_rules"], entry["tools"], catalog)
                        if asset["type"] != "mcp":
                            continue
                        if not account["catalog_refreshed_at"] or now() - account["catalog_refreshed_at"] > 300000:
                            raise GatewayError("CATALOG_STALE", f"请先刷新上游工具目录（{account['name']}）")
                        versions[entry["account_id"]] = {name: catalog[name]["spec_hash"] for name in entry["tools"]}
                    submitted = body.get("tool_versions", {})
                    if not isinstance(submitted, dict) or any(
                        not isinstance(hashes, dict) for hashes in submitted.values()
                    ):
                        raise GatewayError("VALIDATION", "工具版本确认信息格式不正确，请重新打开授权组")
                    if old and "tool_versions" not in body:
                        submitted = {
                            account_id: {name: hashes.get(name) for name in expected}
                            for account_id, expected in versions.items()
                            for hashes in [old["tool_versions"].get(account_id, {})]
                        }
                    if versions != submitted:
                        raise GatewayError("CATALOG_CHANGED", "工具定义已变更，请查看后重新确认", 409)
                record.update(
                    tools_json=dumps(sorted({tool for entry in entries for tool in entry["tools"]})),
                    tool_versions_json=dumps(versions),
                )
            if old:
                record.pop("id")
                record["revision"] = old["revision"] + 1
                conn.execute(
                    f"UPDATE {table} SET {','.join(k + '=?' for k in record)} WHERE id=?", (*record.values(), identity)
                )
            else:
                record["created_at"] = now()
                conn.execute(
                    f"INSERT INTO {table}({','.join(record)}) VALUES({','.join('?' for _ in record)})",
                    tuple(record.values()),
                )
            if table == "grants" and not revoking:
                conn.execute("DELETE FROM grant_clients WHERE grant_id=?", (value["id"],))
                conn.executemany(
                    "INSERT INTO grant_clients(grant_id,client_id) VALUES(?,?)",
                    [(value["id"], member) for member in client_ids],
                )
                conn.execute("DELETE FROM grant_accounts WHERE grant_id=?", (value["id"],))
                conn.executemany(
                    "INSERT INTO grant_accounts(grant_id,account_id,tools_json,parameter_rules_json) VALUES(?,?,?,?)",
                    [
                        (value["id"], entry["account_id"], dumps(entry["tools"]), dumps(entry["parameter_rules"]))
                        for entry in entries
                    ],
                )
            audit(
                conn,
                f"{table}.{'update' if old else 'create'}",
                actor["id"],
                detail_json=dumps(
                    {
                        "id": value["id"],
                        "name": record["name"],
                        "changed_fields": sorted(body),
                        "revision": (old or {}).get("revision", 0) + 1,
                    }
                ),
            )
            saved = public(fetch(conn, table, value["id"]))
            if table == "grants":
                with_targets(conn, saved)
        if returned_token:
            saved["token"] = returned_token
        return saved

    def delete(self, table, identity, revision, actor):
        with self.store.connect(write=True) as conn:
            old = fetch(conn, table, identity)
            if old["revision"] != revision:
                raise GatewayError("CONFLICT", "版本冲突，请刷新", 409)
            conn.execute(f"DELETE FROM {table} WHERE id=?", (identity,))
            if table != "grants":
                reserved = self.store.settings(conn).get("reserved_ids", [])
                reserved.append(identity)
                conn.execute(
                    "INSERT INTO settings(key,value_json,updated_at) VALUES('reserved_ids',?,?) "
                    "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,revision=revision+1,updated_at=excluded.updated_at",
                    (dumps(reserved), now()),
                )
            audit(conn, f"{table}.delete", actor["id"], detail_json=dumps({"id": identity, "name": old.get("name")}))
        return {"deleted": True}

    def rotate(self, identity, revision, actor):
        token = new_token()
        with self.store.connect(write=True) as conn:
            value = fetch(conn, "clients", identity)
            if type(revision) is not int or value["revision"] != revision:
                raise GatewayError("CONFLICT", "版本冲突，请刷新", 409)
            conn.execute(
                "UPDATE clients SET token_hash=?,token_tail=?,revision=revision+1,updated_at=? WHERE id=?",
                (digest(token), token[-4:], now(), identity),
            )
            audit(conn, "clients.rotate", actor["id"], client_id=identity)
        return {"token": token, "token_tail": token[-4:]}

    def settings(self):
        with self.store.connect() as conn:
            return [
                {"key": row["key"], "value": json.loads(row["value_json"]), "revision": row["revision"]}
                for row in conn.execute("SELECT * FROM settings")
                if row["key"] in DEFAULTS
            ]

    def update_settings(self, changes, actor):
        if not isinstance(changes, list):
            raise GatewayError("VALIDATION", "设置更新需要数组")
        with self.store.connect(write=True) as conn:
            for change in changes:
                if (
                    not isinstance(change, dict)
                    or not isinstance(change.get("key"), str)
                    or type(change.get("revision")) is not int
                ):
                    raise GatewayError("VALIDATION", "设置项必须包含 key、value 和整数 revision")
                key, value = change.get("key"), change.get("value")
                if key not in LIMITS or type(value) is not int or not LIMITS[key][0] <= value <= LIMITS[key][1]:
                    raise GatewayError("VALIDATION", "设置值超出支持范围")
                changed = conn.execute(
                    "UPDATE settings SET value_json=?,revision=revision+1,updated_at=? WHERE key=? AND revision=?",
                    (dumps(value), now(), key, change.get("revision")),
                ).rowcount
                if not changed:
                    raise GatewayError("CONFLICT", "设置已变化，请刷新", 409)
            audit(conn, "settings.update", actor["id"], detail_json=dumps({"keys": [c["key"] for c in changes]}))
        return self.settings()

    def audits(self, filters, limit=20, cursor=None):
        conditions, values = [], []
        for key in ("client_id", "asset_id", "tool", "status", "source", "event"):
            if filters.get(key):
                conditions.append(key + "=?")
                values.append(filters[key])
        bounds = {}
        try:
            for key, comparator in (("start", ">="), ("end", "<=")):
                if filters.get(key) not in (None, ""):
                    stamp = int(filters[key])
                    if not 0 <= stamp <= 253402300799999:
                        raise ValueError
                    bounds[key] = stamp
                    conditions.append("ts" + comparator + "?")
                    values.append(stamp)
            if bounds.get("start", 0) > bounds.get("end", 253402300799999):
                raise ValueError
            if cursor:
                stamp, identity = map(int, cursor.split(":"))
                if not 0 <= stamp <= 253402300799999 or not 0 < identity <= 9223372036854775807:
                    raise ValueError
                conditions.append("(ts < ? OR (ts=? AND id<?))")
                values.extend((stamp, stamp, identity))
        except (ValueError, TypeError):
            raise GatewayError("AUDIT_FILTER", "时间范围或分页游标无效", 400) from None
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        with self.store.connect() as conn:
            rows = [
                decode(r)
                for r in conn.execute(
                    "SELECT * FROM audit_log" + where + " ORDER BY ts DESC,id DESC LIMIT ?", (*values, limit + 1)
                )
            ]
        more = len(rows) > limit
        rows = rows[:limit]
        return {"items": rows, "next_cursor": f"{rows[-1]['ts']}:{rows[-1]['id']}" if more else None}

    def dashboard(self):
        end = now()
        start = end - 86400000
        today = datetime.datetime.fromtimestamp(end / 1000, datetime.UTC).date()
        days = [(today - datetime.timedelta(days=i)).isoformat() for i in range(6, -1, -1)]
        week_start = (end // 86400000 - 6) * 86400000
        with self.store.connect() as conn:
            counts = {table: conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0] for table in TABLES}
            statuses = dict(
                conn.execute(
                    "SELECT status,count(*) FROM audit_log WHERE ts BETWEEN ? AND ? GROUP BY status", (start, end)
                )
            )
            call_statuses = dict(
                conn.execute(
                    "SELECT status,count(*) FROM audit_log WHERE event='tools.call' AND ts BETWEEN ? AND ? GROUP BY status",
                    (start, end),
                )
            )
            average = conn.execute(
                "SELECT avg(elapsed_ms) FROM audit_log WHERE event='tools.call' AND status!='started' "
                "AND ts BETWEEN ? AND ?",
                (start, end),
            ).fetchone()[0]
            daily_counts = dict(
                conn.execute(
                    "SELECT strftime('%Y-%m-%d',ts/1000,'unixepoch'),count(*) FROM audit_log "
                    "WHERE event='tools.call' AND ts BETWEEN ? AND ? GROUP BY 1",
                    (week_start, end),
                )
            )
            rankings = {}
            for field in ("tool", "client_id"):
                rankings[field] = [
                    dict(row)
                    for row in conn.execute(
                        f"SELECT {field} AS name,count(*) AS total,"
                        "sum(status IN ('error','denied','timeout','interrupted')) AS failures "
                        "FROM audit_log WHERE event='tools.call' AND ts BETWEEN ? AND ? "
                        f"AND {field} IS NOT NULL GROUP BY {field} ORDER BY total DESC,name LIMIT 5",
                        (start, end),
                    )
                ]
        total = sum(call_statuses.values())
        completed = total - call_statuses.get("started", 0)
        return {
            "counts": counts,
            "statuses": statuses,
            "calls": {
                "total": total,
                "completed": completed,
                "statuses": call_statuses,
                "success_rate": round(call_statuses.get("ok", 0) / completed * 100, 1) if completed else None,
                "average_elapsed_ms": round(average, 1) if average is not None else None,
            },
            "daily": [{"day": day, "total": daily_counts.get(day, 0)} for day in days],
            "top_tools": rankings["tool"],
            "top_clients": rankings["client_id"],
            "start": start,
            "end": end,
            "timezone": "UTC",
            "window": "最近 24 小时",
            "version": "2.5.0",
        }
