#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
compose=(docker compose --project-directory "$root" -f "$root/docker-compose.yml")
mode="${1:-}"
case "$mode" in
  --init|--upgrade) ;;
  *) printf '%s\n' '用法：bash deploy.sh --init 或 --upgrade。仅操作当前 Docker context；不会 SSH 或推送。' >&2; exit 2 ;;
esac
if [[ ! -f "$root/.env" ]]; then
  printf '%s\n' '缺少 .env；请先运行 python -m app.cli setup 并配置部署参数。' >&2
  exit 2
fi
"${compose[@]}" config --quiet
if [[ "$mode" == --init ]]; then
  "${compose[@]}" run --rm --no-deps gateway python -m app.cli init-admin --generate-password
else
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  "${compose[@]}" exec -T gateway python -m app.cli backup "/app/backups/pre-upgrade-${stamp}.sqlite"
  "${compose[@]}" stop gateway
  printf '%s\n' '旧实例已停止。后续若失败，保持停止状态；勿用旧镜像直接打开已迁移的数据库。'
  "${compose[@]}" run --rm --no-deps gateway python -m app.cli migrate
fi
"${compose[@]}" up -d --no-deps --no-build --wait --wait-timeout 90 gateway
"${compose[@]}" ps
printf '%s\n' '网关已启动。首次登录后请修改初始密码；主密钥需独立备份。'
