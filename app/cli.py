import argparse
import getpass
import os
import re
import secrets
import stat

from cryptography.fernet import Fernet
from dotenv import load_dotenv

from app.core.config import Config
from app.core.db import dumps, now
from app.core.gateway import Gateway
from app.core.manager import audit
from app.core.security import Vault


def main():
    parser = argparse.ArgumentParser(description="MCP 资产网关本地维护工具")
    sub = parser.add_subparsers(dest="command", required=True)
    setup = sub.add_parser("setup", help="创建本地 .env，不覆盖已有文件")
    setup.add_argument("--public-url", default="http://localhost:8303")
    sub.add_parser("migrate", help="迁移数据库，需停止正在运行的应用")
    init = sub.add_parser("init-admin", help="首次初始化管理员")
    init.add_argument("--username", default="admin")
    init.add_argument("--generate-password", action="store_true", help="生成并仅展示一次随机初始密码")
    backup = sub.add_parser("backup", help="在线一致备份，无需停止应用")
    backup.add_argument("destination")
    rotate = sub.add_parser("rotate-key", help="离线轮换密钥；新密钥从受限文件读取，不从参数读取")
    rotate.add_argument("--key-file", required=True)
    rotate.add_argument("--key-id", required=True)
    rotate.add_argument("--backup", help="轮换前一致备份的新文件路径；默认写入数据库所在目录")
    args = parser.parse_args()
    os.umask(0o077)
    if args.command == "setup":
        if any(c in args.public_url for c in "\r\n'"):
            parser.error("public-url 包含非法字符")
        key = Fernet.generate_key().decode()
        value = f"GATEWAY_MASTER_KEY={key}\nGATEWAY_MASTER_KEY_ID=key-1\nDATABASE_PATH=data/gateway.db\nPUBLIC_BASE_URL={args.public_url}\nCOOKIE_SECURE={'true' if args.public_url.startswith('https:') else 'false'}\nOUTBOUND_ALLOWLIST=null\nLEGACY_COMPAT=false\nSSH_HOST_KEY_ENFORCE=false\nIMAGE_TAG=0.1.0\n"
        with open(".env", "x") as output:
            output.write(value)
        print("已创建权限受限的 .env；请独立备份主密钥；需要出站管控时再填写 OUTBOUND_ALLOWLIST。")
        return
    load_dotenv()
    gateway = Gateway(Config.from_env())
    try:
        if args.command == "backup":
            print(gateway.store.backup(args.destination))
            return
        gateway.store.acquire()
        gateway.store.migrate()
        gateway.manager.check_all_credentials()
        if args.command == "init-admin":
            password = (
                secrets.token_urlsafe(24) if args.generate_password else getpass.getpass("管理员密码（12～72 字节）：")
            )
            if not args.generate_password and password != getpass.getpass("再次输入密码："):
                parser.error("两次密码不一致")
            gateway.manager.init_admin(args.username, password)
            print("管理员已初始化：" + args.username)
            if args.generate_password:
                print("一次性初始密码：" + password)
        elif args.command == "rotate-key":
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", args.key_id):
                parser.error("新密钥 ID 必须为 1～64 位字母、数字、点、下划线或连字符，且以字母或数字开头")
            if args.key_id == gateway.vault.key_id:
                parser.error("新密钥 ID 必须不同")
            try:
                fd = os.open(args.key_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, "rb") as source:
                    info = os.fstat(source.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
                        parser.error("新密钥必须为当前用户拥有的普通文件，且仅允许所属用户读写")
                    key = source.read(1025).strip().decode("ascii")
                if len(key) != 44:
                    raise ValueError
                new = Vault(key, args.key_id)
            except (OSError, ValueError):
                parser.error("新密钥文件不可读、不是安全的普通文件或 Fernet 格式无效")
            if key == gateway.config.master_key:
                parser.error("新主密钥必须与旧主密钥不同")
            destination = args.backup or gateway.store.path.with_name(
                f"gateway-before-key-rotation-{secrets.token_hex(8)}.sqlite"
            )
            backup_path = gateway.store.backup(destination)
            print("轮换前数据库备份：" + backup_path + "；此备份须与旧主密钥配对保存。")
            with gateway.store.connect(write=True) as conn:
                count = 0
                for row in conn.execute("SELECT id,credential_ciphertext,credential_key_id FROM accounts"):
                    if row[1] is not None:
                        value = gateway.vault.decrypt(row[1], row[2])
                        cipher = new.encrypt(value)
                        conn.execute(
                            "UPDATE accounts SET credential_ciphertext=?,credential_key_id=?,"
                            "revision=revision+1,updated_at=? WHERE id=?",
                            (cipher, args.key_id, now(), row[0]),
                        )
                        count += 1
                for row in conn.execute("SELECT credential_ciphertext,credential_key_id FROM accounts"):
                    new.decrypt(row[0], row[1])
                audit(
                    conn,
                    "credentials.rotate-key",
                    source="system",
                    detail_json=dumps(
                        {
                            "old_key_id": gateway.vault.key_id,
                            "new_key_id": args.key_id,
                            "accounts": count,
                        }
                    ),
                )
            print(
                "数据库密钥轮换已提交并验证。启动前更新 GATEWAY_MASTER_KEY 和 GATEWAY_MASTER_KEY_ID，并配对备份；旧密钥不可再解密当前库。"
            )
        else:
            print("迁移完成。")
    finally:
        gateway.store.release()
        gateway.pool.shutdown(wait=True)
        gateway.runner.close()


if __name__ == "__main__":
    main()
