import fcntl
import hashlib
import json
import os
import shlex
import sqlite3
import time
from contextlib import closing, contextmanager
from pathlib import Path

from app.core.config import DEFAULTS


def now():
    return int(time.time() * 1000)


def dumps(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def decode(row):
    if row is None:
        return None
    result = dict(row)
    for key in list(result):
        if key.endswith("_json"):
            result[key[:-5]] = json.loads(result.pop(key))
    return result


class Store:
    def __init__(self, path):
        self.path = Path(path).resolve()
        self.lock = None

    @contextmanager
    def connect(self, write=False, foreign_keys=True):
        conn = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA foreign_keys={'ON' if foreign_keys else 'OFF'}")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA synchronous=FULL")
        try:
            conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def acquire(self):
        os.umask(0o077)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = open(str(self.path) + ".lock", "a")
        try:
            fcntl.flock(self.lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.lock.close()
            self.lock = None
            raise RuntimeError("该数据目录已有运行实例或维护任务") from None

    def release(self):
        if self.lock:
            self.lock.close()
            self.lock = None

    def migrate(self):
        with closing(sqlite3.connect(self.path)) as conn:
            if conn.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise RuntimeError("数据库完整性校验失败")
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, "
                "checksum TEXT NOT NULL, applied_at INTEGER NOT NULL)"
            )
            conn.commit()
        files = sorted((Path(__file__).parent / "migrations").glob("*.sql"))
        with self.connect() as conn:
            current = {r[0]: r[1] for r in conn.execute("SELECT version,checksum FROM schema_migrations")}
        if any(v not in {int(f.stem) for f in files} for v in current):
            raise RuntimeError("数据库版本高于当前程序，拒绝启动")
        for file in files:
            version = int(file.stem)
            script = file.read_text()
            checksum = hashlib.sha256(script.encode()).hexdigest()
            if version in current:
                if current[version] != checksum:
                    raise RuntimeError("迁移文件 checksum 不一致")
                continue
            # @foreign-keys-off 指令供表重建类迁移关闭外键，提交前用 foreign_key_check 兜底验证。
            foreign_keys = "-- @foreign-keys-off" not in script
            with self.connect(write=True, foreign_keys=foreign_keys) as conn:
                if version == 7:
                    # 保留旧 SSH 执行时的分词与引用语义，避免迁移后通配符等被 shell 展开。
                    conn.create_function(
                        "legacy_ssh_command",
                        1,
                        lambda value: shlex.join(shlex.split(value, posix=True)),
                        deterministic=True,
                    )
                # 按完整语句执行，避免 executescript 隐式提交导致半迁移。
                statement = ""
                for line in script.splitlines(keepends=True):
                    statement += line
                    if sqlite3.complete_statement(statement):
                        conn.execute(statement)
                        statement = ""
                if statement.strip():
                    raise RuntimeError("迁移存在未完成 SQL")
                if not foreign_keys and conn.execute("PRAGMA foreign_key_check").fetchall():
                    raise RuntimeError("迁移破坏了外键约束")
                conn.execute("INSERT INTO schema_migrations VALUES (?,?,?)", (version, checksum, now()))
        with self.connect(write=True) as conn:
            for key, value in DEFAULTS.items():
                conn.execute(
                    "INSERT OR IGNORE INTO settings(key,value_json,updated_at) VALUES(?,?,?)",
                    (key, dumps(value), now()),
                )
            conn.execute(
                "UPDATE audit_log SET status='interrupted',completed_at=?,error_code='PROCESS_INTERRUPTED' "
                "WHERE status='started'",
                (now(),),
            )

    def settings(self, conn=None):
        if conn is None:
            with self.connect() as current:
                return self.settings(current)
        return {r["key"]: json.loads(r["value_json"]) for r in conn.execute("SELECT * FROM settings")}

    def backup(self, destination):
        destination = Path(destination).resolve()
        if destination == self.path or destination.exists():
            raise ValueError("备份必须写入新的独立文件")
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = destination.with_suffix(destination.suffix + ".partial")
        if temporary.exists():
            raise ValueError("存在未完成备份，请先检查")
        with closing(sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True)) as source:
            fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
            with closing(sqlite3.connect(temporary)) as target:
                source.backup(target, pages=100, sleep=0.02)
                if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise RuntimeError("备份完整性校验失败")
        os.link(temporary, destination)
        temporary.unlink()
        return str(destination)
