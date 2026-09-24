"""按逻辑行有界读取日志；游标为网关专用，不使用 Jenkins 原始存储偏移。"""

import base64
import codecs
import hashlib
import hmac
import json
from collections import deque

import regex

from app.core.security import GatewayError


class ScanLimit(Exception):
    pass


class LogCursor:
    def __init__(self, key):
        self.key = hashlib.sha256(b"jenkins-log-cursor-v1:" + key.encode()).digest()

    def encode(self, ctx, job, build, position):
        payload = json.dumps(
            [1, ctx.asset["id"], ctx.account["id"], job, build, position], separators=(",", ":")
        ).encode()
        signature = hmac.digest(self.key, payload, "sha256")
        return base64.urlsafe_b64encode(signature + payload).decode().rstrip("=")

    def decode(self, token, ctx, job, build=None):
        try:
            raw = base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
            signature, payload = raw[:32], raw[32:]
            if not hmac.compare_digest(signature, hmac.digest(self.key, payload, "sha256")):
                raise ValueError
            values = json.loads(payload)
            if (
                len(values) != 6
                or values[:4] != [1, ctx.asset["id"], ctx.account["id"], job]
                or type(values[4]) is not int
                or values[4] < 1
                or type(values[5]) is not int
                or values[5] < 0
                or (build is not None and values[4] != build)
            ):
                raise ValueError
            return values[4], values[5]
        except (ValueError, TypeError, IndexError, KeyError):
            raise GatewayError("JENKINS_CURSOR", "日志游标无效或不属于当前资产、账号、任务及构建") from None


async def lines(response, ctx, budget):
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    pending, used, clipped = "", 0, False
    chars = ctx.limits["max_cell_chars"]
    token = ctx.credential["api_token"]
    auth = base64.b64encode((ctx.account["config"]["username"] + ":" + token).encode()).decode()
    retain = chars + max(len(token), len(auth))
    secrets = regex.compile("|".join(regex.escape(s) for s in sorted((token, auth), key=len, reverse=True)))

    def visible(value):
        # 原始长行被裁剪时连同边界上的凭据前缀脱敏，避免多次替换缩短文本后暴露前缀。
        parts, start = [], 0
        for match in secrets.finditer(value, partial=clipped):
            if match.start() == match.end():
                continue
            parts.extend((value[start : match.start()], "[REDACTED]"))
            start = match.end()
        parts.append(value[start:])
        return "".join(parts)[:chars].rstrip("\r")

    async for chunk in response.aiter_bytes(chunk_size=8192):
        ctx.remaining()
        allowed = max(0, budget - used)
        used += len(chunk)
        text = decoder.decode(chunk[:allowed])
        pieces = text.split("\n")
        for index, piece in enumerate(pieces):
            if len(pending) + len(piece) > chars:
                ctx.stats["truncated"] = True
            clipped |= len(pending) + len(piece) > retain
            pending = (pending + piece)[:retain]
            if index < len(pieces) - 1:
                yield visible(pending)
                pending, clipped = "", False
        if used > budget:
            raise ScanLimit
    suffix = decoder.decode(b"", final=True)
    if pending or suffix:
        ctx.stats["jenkins_partial_line"] = True
        yield visible(pending + suffix)


async def read_log(http, ctx, args, path, build, cursor):
    skip = args.get("skip", 0)
    if args.get("cursor"):
        _, skip = cursor.decode(args["cursor"], ctx, args["jobFullName"], build)
    requested = args.get("limit", 100) or 100
    limit = min(abs(requested), ctx.limits["max_result_rows"])
    tail = not args.get("cursor") and (skip < 0 or (skip == 0 and requested < 0))
    if skip > 0 and requested < 0 and not args.get("cursor"):
        skip = max(0, skip - limit)
    budget = ctx.account["policy"].get("max_log_scan_bytes", 8 * 1024 * 1024)
    # 即使使用尾部环形缓冲，也不能分配超过最终输出预算的文本。
    output_budget = max(1, (ctx.limits["max_output_bytes"] - 768) // 4)
    rows, scanned, used, complete, scan_limited = deque(), 0, 0, False, False
    tail_count = (-skip + (limit if requested < 0 else 0)) if tail else 0
    if tail_count > ctx.limits["max_result_rows"]:
        raise GatewayError("JENKINS_LOG_WINDOW", "尾部窗口超过账号结果行上限，请减小负 skip/limit")
    async with http.stream(path + "consoleText") as response:
        try:
            async for line in lines(response, ctx, budget):
                scanned += 1
                if not tail and scanned <= skip:
                    continue
                size = len(json.dumps(line, ensure_ascii=False).encode())
                if tail_count:
                    rows.append((scanned, line, size))
                    used += size
                    while len(rows) > tail_count or used > output_budget:
                        _, _, removed = rows.popleft()
                        used -= removed
                        if used + removed > output_budget:
                            ctx.stats["truncated"] = True
                else:
                    if used + size > output_budget:
                        scanned -= 1
                        ctx.stats["truncated"] = True
                        break
                    rows.append((scanned, line, size))
                    used += size
                    if len(rows) >= limit:
                        break
            else:
                complete = True
        except ScanLimit:
            scan_limited = True
    if tail:
        if complete:
            start = max(0, scanned + skip - (limit if requested < 0 else 0))
            rows = deque(row for row in rows if start < row[0] <= start + limit)
        else:
            # 未扫到末尾时，缓冲区不是日志真正尾部。
            rows.clear()
    position = rows[-1][0] if rows else max(scanned, skip)
    if ctx.stats.get("jenkins_partial_line") and position == scanned:
        # 正在写入的末行下次重新读取，避免后续追加内容被逻辑行游标跳过。
        position = max(0, position - 1)
    if not rows and not complete and not scan_limited and not tail:
        raise GatewayError("OUTPUT_LIMIT", "单行日志超过输出预算，请提高输出限制或减少单元格长度")
    return {
        "buildNumber": build,
        "lines": [r[1] for r in rows],
        "startLine": rows[0][0] if rows else None,
        "totalLines": scanned if complete else None,
        "snapshotComplete": complete,
        "scanLimited": scan_limited,
        "truncated": not complete or bool(ctx.stats.get("truncated")),
        "nextCursor": cursor.encode(ctx, args["jobFullName"], build, position) if not tail or complete else None,
        "cursorNote": "按逻辑行重新扫描；运行中构建可继续追加日志",
    }


async def search_log(http, ctx, args, path, build):
    flags = regex.IGNORECASE if args.get("ignoreCase", False) else 0
    pattern = args["pattern"] if args.get("useRegex", False) else regex.escape(args["pattern"])
    try:
        compiled = regex.compile(pattern, flags)
    except regex.error:
        raise GatewayError("JENKINS_LOG_PATTERN", "日志搜索正则无效") from None
    context = args.get("contextLines", 0)
    maximum = min(args.get("maxMatches", 100), ctx.limits["max_result_rows"])
    before, matches, count, limited, complete = deque(maxlen=context), [], 0, False, False
    budget = ctx.account["policy"].get("max_log_scan_bytes", 8 * 1024 * 1024)
    output_budget = max(1, (ctx.limits["max_output_bytes"] - 512) // 4)
    async with http.stream(path + "consoleText") as response:
        try:
            async for line in lines(response, ctx, budget):
                count += 1
                for match in matches:
                    if count <= match["lineNumber"] + context:
                        match["after"].append(line)
                try:
                    found = len(matches) < maximum and compiled.search(line, timeout=min(0.02, ctx.remaining()))
                except TimeoutError:
                    raise GatewayError("JENKINS_LOG_REGEX_TIMEOUT", "日志搜索正则超过执行时间限制") from None
                if found:
                    matches.append({"lineNumber": count, "line": line, "before": list(before), "after": []})
                before.append(line)
                if len(json.dumps(matches, ensure_ascii=False).encode()) > output_budget:
                    matches.pop()
                    limited = True
                    break
                if len(matches) >= maximum and count >= matches[-1]["lineNumber"] + context:
                    limited = True
                    break
            else:
                complete = True
        except ScanLimit:
            limited = True
    return {
        "buildNumber": build,
        "matches": matches,
        "scannedLines": count,
        "totalLines": count if complete else None,
        "scanComplete": complete,
        "truncated": limited or bool(ctx.stats.get("truncated")),
    }
