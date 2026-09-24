#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
tag="${IMAGE_TAG:-0.1.0}"
image="${IMAGE_NAME:-mcp-asset-gateway}:$tag"
mode="${1:---build}"
case "$mode" in
  --build|--push|--remote) ;;
  *) printf '%s\n' '用法：bash build-and-push.sh [--build|--push|--remote]；通过 IMAGE_NAME / IMAGE_TAG 指定版本；--remote 在目标服务器原生构建并推送私有 registry。' >&2; exit 2 ;;
esac
if [[ ! "$tag" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ || "$tag" == latest ]]; then
  printf '%s\n' '请指定有效、可追溯的 IMAGE_TAG；不支持 latest。' >&2
  exit 2
fi
if [[ "$mode" == --remote ]]; then
  server="${SERVER:?请显式设置 SERVER，例如 deploy@build.example.com}"
  base_dir="${BASE_DIR:-/opt/mcp-asset-gateway}"
  registry="${REGISTRY:?请显式设置 REGISTRY，例如 ghcr.io}"
  image_path="${REMOTE_IMAGE:?请显式设置 REMOTE_IMAGE，例如 owner/mcp-asset-gateway}"
  if [[ ! "$server" =~ ^[A-Za-z0-9_][A-Za-z0-9_.@-]*$ ||
        ! "$base_dir" =~ ^/[A-Za-z0-9_/-]+$ || "$base_dir" == / ||
        ! "$registry" =~ ^[a-z0-9][a-z0-9.:-]*$ ||
        ! "$image_path" =~ ^[a-z0-9][a-z0-9_/-]*$ ]]; then
    printf '%s\n' '远程构建参数格式不合法；路径和目标不能包含空格或 shell 特殊字符。' >&2
    exit 2
  fi
  printf '远程构建：同步构建上下文到 %s:%s/build，原生构建并推送 %s/%s:%s。\n' \
    "$server" "$base_dir" "$registry" "$image_path" "$tag"
  COPYFILE_DISABLE=1 tar czf - -C "$root" --exclude='web/node_modules' --exclude='__pycache__' \
    --exclude='._*' --exclude='.env*' --exclude='*.key' --exclude='*.pem' \
    app web Dockerfile requirements.lock .dockerignore \
    | ssh "$server" "mkdir -p $base_dir/build && mkdir $base_dir/build/$tag && tar xzf - -C $base_dir/build/$tag"
  scp -q "$root/docker-compose.yml" "$root/deploy.sh" "$root/.env.example" "$server:$base_dir/"
  # 构建机可能是离线的，使用已存在的基础镜像；需要强制刷新时自行预先 docker pull。
  ssh "$server" "docker build --tag $registry/$image_path:$tag $base_dir/build/$tag"
  ssh "$server" "docker push $registry/$image_path:$tag"
  printf '完成。首次部署先准备 %s:%s/.env，再执行 bash %s/deploy.sh --init；版本升级执行 bash %s/deploy.sh --upgrade。\n' \
    "$server" "$base_dir" "$base_dir" "$base_dir"
  exit 0
fi
if [[ "$mode" == --push && -z "${IMAGE_NAME:-}" ]]; then
  printf '%s\n' '--push 必须显式设置带命名空间的 IMAGE_NAME，并预先登录目标仓库。' >&2
  exit 2
fi
docker build --pull --tag "$image" "$root"
if [[ "$mode" == --push ]]; then
  printf '将推送镜像 %s；登录镜像仓库由操作员预先完成。\n' "$image"
  docker push "$image"
else
  printf '镜像已构建：%s；未推送，也未部署。\n' "$image"
fi
