import fnmatch
import posixpath
import stat

from app.asset_types.base import RESOURCE_SCHEMA, AssetType, integer, obj, result, text, tool
from app.asset_types.ssh import SSH_ACCOUNT, SSH_CREDENTIAL, connect_ssh, ssh_connection_schema
from app.core.security import GatewayError


def safe_path(sftp, root, relative):
    if relative.startswith("/") or "\\" in relative or "\0" in relative or ".." in relative.split("/"):
        raise GatewayError(
            "PATH_DENIED",
            "仅允许账号只读根目录内的相对路径；“/”开头的绝对路径请改用“.”表示根目录",
            403,
        )
    combined = posixpath.normpath(posixpath.join(root, relative))
    cursor = "/"
    for part in combined.split("/"):
        if not part:
            continue
        cursor = posixpath.join(cursor, part)
        info = sftp.lstat(cursor)
        if stat.S_ISLNK(info.st_mode):
            raise GatewayError("SYMLINK_DENIED", "不允许跟随符号链接", 403)
    normalized_root = sftp.normalize(root).rstrip("/") or "/"
    normalized = sftp.normalize(combined)
    if posixpath.commonpath([normalized_root, normalized]) != normalized_root:
        raise GatewayError("PATH_DENIED", "路径超出账号根目录", 403)
    return normalized


def metadata(item, path):
    mode = item.st_mode or 0
    kind = (
        "directory"
        if stat.S_ISDIR(mode)
        else "file"
        if stat.S_ISREG(mode)
        else "link"
        if stat.S_ISLNK(mode)
        else "special"
    )
    return {"name": item.filename, "path": path, "type": kind, "size": item.st_size, "modified_at": item.st_mtime}


class SFTPAssetType(AssetType):
    type_id, display_name, icon = "filebrowser", "SFTP 文件目录", "FolderOpened"
    default_port = 22
    account_schema, credential_schema = SSH_ACCOUNT, SSH_CREDENTIAL

    def __init__(self, enforce_host_key=True):
        self.enforce_host_key = enforce_host_key
        self.connection_schema = ssh_connection_schema(enforce_host_key)

    policy_schema = obj(
        {
            **RESOURCE_SCHEMA,
            "root_dir": text("只读根目录", minLength=1, pattern=r"^/"),
            "max_depth": integer("搜索深度", 1, 5, default=5),
            "max_scan": integer("扫描项数", 1, 5000, default=5000),
            "max_read_bytes": integer("读取字节", 1, 262144, default=262144),
        },
        ["root_dir"],
    )
    tools = [
        tool(
            "list_dir",
            "只读列举指定目录的一层子项（不递归），不跟随软链接。"
            "path 为相对路径：相对账号的只读根目录，根目录本身用“.”（默认），子目录如“logs”。"
            "不接受“/”开头的绝对路径、“..”或超出根目录的路径。",
            {
                "path": text(
                    "相对路径",
                    default=".",
                    description="相对账号只读根目录；根目录用“.”（默认），如“logs”、“conf/nginx”；不要传“/”开头的绝对路径",
                ),
                "limit": integer("项目数", 1, 500, default=100),
            },
        ),
        tool(
            "search_files",
            "按文件名 glob 搜索，不搜索文件正文，受扫描深度和数量限制。"
            "path 为相对路径：相对账号的只读根目录的起始目录，根目录本身用“.”（默认）。",
            {
                "path": text(
                    "起始相对路径",
                    default=".",
                    description="相对账号只读根目录的起始目录；根目录用“.”（默认）；不要传“/”开头的绝对路径",
                ),
                "pattern": text("文件名模式", minLength=1, maxLength=128),
                "max_results": integer("返回数量", 1, 200, default=100),
            },
            ["pattern"],
        ),
        tool(
            "read_file",
            "读取普通 UTF-8 文本文件的一段；不读取二进制或特殊文件。"
            "path 为相对路径：相对账号的只读根目录，如“logs/app.log”。",
            {
                "path": text(
                    "相对路径",
                    minLength=1,
                    description="相对账号只读根目录的文件路径，如“logs/app.log”；不要传“/”开头的绝对路径",
                ),
                "offset": integer("字节偏移", 0, default=0),
                "max_bytes": integer("读取字节", 1, 262144, default=65536),
            },
            ["path"],
        ),
    ]

    def validate_config(self, connection, account, policy, credential):
        super().validate_config(connection, account, policy, credential)
        root = policy["root_dir"]
        if ".." in root.split("/") or "\\" in root or "\0" in root:
            raise GatewayError("PATH_DENIED", "根目录配置不合法")

    def execute_sync(self, name, args, ctx):
        client = connect_ssh(ctx)
        sftp = client.open_sftp()
        ctx.add_closer(sftp.close)
        sftp.get_channel().settimeout(min(ctx.remaining(), 5))
        policy, relative = ctx.account["policy"], args.get("path", ".")
        root = policy["root_dir"]
        path = safe_path(sftp, root, relative)
        try:
            if name == "read_file":
                before = sftp.lstat(path)
                if not stat.S_ISREG(before.st_mode):
                    raise GatewayError("FILE_TYPE", "只允许读取普通文件")
                amount = min(
                    args.get("max_bytes", 65536),
                    policy.get("max_read_bytes", 262144),
                    ctx.limits["max_output_bytes"] // 8,
                )
                offset = args.get("offset", 0)
                with sftp.open(path, "rb", bufsize=0) as handle:
                    after = handle.stat()
                    if (
                        not stat.S_ISREG(after.st_mode)
                        or before.st_size != after.st_size
                        or before.st_mtime != after.st_mtime
                    ):
                        raise GatewayError("FILE_CHANGED", "读取时文件发生变化，请重试")
                    ctx.remaining()
                    handle.seek(offset)
                    raw = handle.read(amount)
                if b"\0" in raw or sum(b < 9 or 13 < b < 32 for b in raw) > max(2, len(raw) // 100):
                    raise GatewayError("BINARY_FILE", "不支持二进制文件")
                cut = offset + len(raw) < after.st_size
                ctx.stats["truncated"] = cut
                return result(
                    {
                        "path": relative,
                        "offset": offset,
                        "bytes": len(raw),
                        "size": after.st_size,
                        "text": raw.decode("utf-8", "replace"),
                        "truncated": cut,
                        "encoding_note": "UTF-8；字节切片跨字符边界时使用替换字符",
                    }
                )
            items, scanned, cut = [], 0, False
            limit = min(
                args.get("limit", 100) if name == "list_dir" else args.get("max_results", 100),
                ctx.limits["max_result_rows"],
            )
            queue = [(path, 0)]
            while queue:
                current, level = queue.pop()
                current = safe_path(sftp, root, posixpath.relpath(current, root))
                for item in sftp.listdir_iter(current, read_aheads=1):
                    ctx.remaining()
                    scanned += 1
                    if scanned > policy.get("max_scan", 5000):
                        cut = True
                        break
                    # 防御恶意 SFTP 服务返回带目录分隔的条目名称。
                    if (
                        item.filename in (".", "..")
                        or "/" in item.filename
                        or "\\" in item.filename
                        or "\0" in item.filename
                    ):
                        continue
                    child = posixpath.join(current, item.filename)
                    meta = metadata(item, posixpath.relpath(child, root))
                    if name == "list_dir" or fnmatch.fnmatchcase(item.filename, args["pattern"]):
                        if len(items) >= limit:
                            cut = True
                            break
                        items.append(meta)
                    if name == "search_files" and meta["type"] == "directory":
                        if level < policy.get("max_depth", 5):
                            queue.append((child, level + 1))
                        else:
                            cut = True
                if scanned > policy.get("max_scan", 5000) or len(items) >= limit:
                    cut = cut or bool(queue)
                    break
                if name == "list_dir":
                    break
            ctx.stats.update(row_count=len(items), truncated=cut)
            return result({"items": items, "scanned": scanned, "truncated": cut})
        finally:
            ctx.close()

    def health_sync(self, ctx):
        client = connect_ssh(ctx)
        sftp = client.open_sftp()
        ctx.add_closer(sftp.close)
        try:
            path = safe_path(sftp, ctx.account["policy"]["root_dir"], ".")
            if not stat.S_ISDIR(sftp.lstat(path).st_mode):
                raise GatewayError("ROOT_INVALID", "根路径不是目录")
            return {"reachable": True}
        finally:
            ctx.close()
