FROM node:22-bookworm-slim AS web
WORKDIR /build/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM python:3.11-slim-bookworm AS runtime
# 构建时可选传入 PIP_INDEX_URL（如国内镜像源）；默认留空使用官方 PyPI，哈希校验不受影响。
ARG PIP_INDEX_URL=""
# 构建时可选传入 DEBIAN_MIRROR（镜像主机根，如 https://mirrors.aliyun.com）；默认留空使用官方 deb.debian.org。
ARG DEBIAN_MIRROR=""
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DEFAULT_TIMEOUT=60 \
    DATABASE_PATH=/app/data/gateway.db
WORKDIR /app
COPY requirements.lock ./
RUN if [ -n "$DEBIAN_MIRROR" ]; then sed -i "s|http://deb.debian.org|$DEBIAN_MIRROR|g" /etc/apt/sources.list.d/debian.sources; fi \
    && apt-get -o Acquire::Retries=3 -o APT::Update::Error-Mode=any update \
    && apt-get -o Acquire::Retries=3 install -y --no-install-recommends git openssh-client ripgrep \
    && rm -rf /var/lib/apt/lists/* \
    && pip install ${PIP_INDEX_URL:+--index-url=$PIP_INDEX_URL} --require-hashes -r requirements.lock \
    && pip check \
    && python -c "import subprocess; assert b'http.curloptResolve' in subprocess.check_output(['git', 'help', '--config']).splitlines()" \
    && groupadd --gid 10001 gateway \
    && useradd --uid 10001 --gid gateway --no-create-home gateway \
    && mkdir -p /app/data /app/backups \
    && chown gateway:gateway /app/data /app/backups
COPY app/ ./app/
COPY --from=web /build/static/ ./static/
USER 10001:10001
EXPOSE 8303
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "app/healthcheck.py"]
# 入口自动分流：配置了主密钥（compose env_file）启动 HTTP 服务；未配置（目录检查、
# 本地直连）进入自举 stdio 模式，响应 MCP introspection。
CMD ["sh", "-c", "if [ -n \"$GATEWAY_MASTER_KEY\" ]; then exec uvicorn app.main:app_factory --factory --host 0.0.0.0 --port 8303 --workers 1 --no-access-log --no-proxy-headers --limit-concurrency 128 --timeout-graceful-shutdown 40; else exec python -m app.stdio_server; fi"]
