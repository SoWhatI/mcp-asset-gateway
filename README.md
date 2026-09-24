# MCP Asset Gateway

English | [简体中文](README.zh-CN.md)

A self-hosted asset gateway that provides AI clients with a single, controlled MCP entry point. Manage assets, account credentials, clients, and authorization groups through a web console, with full tool-call auditing.

## Features

| Type | Highlights |
|---|---|
| MySQL | Read-only queries and schema reads by default; restricted INSERT/UPDATE/DELETE after `allow_write` is explicitly enabled per account, with mandatory WHERE on UPDATE/DELETE |
| SSH | Non-interactive command execution; command arguments controlled by per-group allow/block lists; no PTY or interactive input |
| FileBrowser | SFTP-based restricted directory browsing and file reading |
| MCP | Forwards upstream tools with per-account approval of tool definition versions |
| Redis | Key scanning and reading within allow-list patterns; write tools enabled explicitly per account policy |
| Kubernetes | Resource listing, details, Pod logs, and non-interactive `k8s_exec`; token or client-certificate auth — see [Kubernetes assets](docs/asset-kubernetes.md) (Chinese) |
| Git repositories | Gateway-hosted read-only code mirrors: code search, file reading, commit history, diffs, directory tree, and branch listing |
| Jenkins | Direct Jenkins HTTP API calls without any MCP plugin; 19 tools for jobs, builds, logs, tests, SCM, and Replay — see [Jenkins assets](docs/asset-jenkins.md) (Chinese) |
| Admin console | Multi-dimensional search in the authorization matrix, group management, tool select-all/clear, parameter allow/block lists (exact/regex), debugging, and audit export |
| Security foundation | Fernet-encrypted credentials, hashed client tokens, admin sessions with CSRF protection, egress target allow-listing, consistent SQLite backups |

## Authorization & Security Model

- An authorization group links multiple clients with multiple asset accounts; each client in the group gets the selected tools that actually exist on each account. Permissions across groups are merged (union), and identically named tools are published once. Full rules: [Authorization groups & parameter rules](docs/authorization.md) (Chinese).
- Tools are unauthorized by default; write operations and high-risk tools (MySQL `allow_write`, Jenkins write tools, `k8s_exec`, etc.) must be checked explicitly in an authorization group.
- Client tokens are shown only once; credentials are stored encrypted; keep the master key separate from the database.
- Optional egress registration restricts reachable targets; loopback, link-local, multicast, and cloud metadata addresses are always denied. An allow-list is not a substitute for a firewall.

## Quick Start

Docker is recommended; Docker and Compose 2.30+ required. No Python needed on the host:

```bash
mkdir mcp-asset-gateway && cd mcp-asset-gateway
curl -fsSLO https://raw.githubusercontent.com/SoWhatI/mcp-asset-gateway/main/docker-compose.yml
docker run --rm ghcr.io/sowhati/mcp-asset-gateway:0.1.0 \
  python -m app.cli setup --public-url https://gateway.example.com --output - > .env
chmod 600 .env
docker compose up -d
docker compose run --rm --no-deps gateway python -m app.cli init-admin --generate-password
```

`gateway.example.com` is a placeholder — replace it with your actual address; use `http://localhost:8303` for local evaluation. Open the console, sign in as admin `admin` with the one-time password, then change it; there is no built-in default password. For image upgrades, reverse proxying, building from source, and backup/restore, see [Deployment & operations](docs/deployment.md) (Chinese); for installation, onboarding, and configuration checklists, see the [User guide](USER_GUIDE.md) (Chinese).

### Run from Source

Requirements: Python 3.11+, Node.js 22 (minimum 20.19), Linux/macOS; on Windows use WSL2 or Docker. Git assets additionally require a system Git with `http.curloptResolve` support and OpenSSH. SQLite WAL and process file locks are used, so a single instance with a single Uvicorn worker is supported; do not place the database on shared network filesystems.

Local evaluation (from the project root):

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock
npm ci --prefix web --no-audit --no-fund
npm run build --prefix web
python -m app.cli setup --public-url http://localhost:8303
python -m app.cli init-admin --generate-password
uvicorn app.main:app_factory --factory --host 127.0.0.1 --port 8303 --workers 1 --no-access-log
```

Open http://localhost:8303, sign in as admin `admin` with the one-time password, then change it. `setup` never overwrites an existing `.env` and supports `--output -` to print to stdout for generating it inside a container.

## Documentation

| Document | Contents |
|---|---|
| [User guide](USER_GUIDE.md) | Installation, first sign-in, asset onboarding, authorization, MCP configuration, backups, FAQ |
| [Authorization groups & parameter rules](docs/authorization.md) | Group model and tool parameter allow/block lists |
| [Kubernetes assets](docs/asset-kubernetes.md) | Account policy, authentication, and `k8s_exec` tool reference |
| [Jenkins assets](docs/asset-jenkins.md) | Native Jenkins tools, permissions, and budgets |
| [Deployment & operations](docs/deployment.md) | Docker build/push/upgrade, data migration, backup & restore |
| [Security policy](SECURITY.md) | Security boundaries, verification scope, private vulnerability reporting |
| [Contributing](CONTRIBUTING.md) | Commit conventions, verification commands, pre-release checklist |
| [Changelog](CHANGELOG.md) | Version history |

The documentation is currently written in Chinese.

## Development & Testing

```bash
python -m pip install -r requirements-dev.txt
ruff check app tests scripts
ruff format --check app tests scripts
python -m pytest -q
npm test --prefix web
npm run build --prefix web
python scripts/release_check.py
```

Default tests never touch real assets; remote contract, Docker lifecycle, and real-browser acceptance tests require explicit configuration and are skipped by default. The isolated local-container acceptance entry point is `python tests/local_stack.py --help`; never configure production assets or credentials for tests.

- `app/asset_types/`: adapters for the eight asset types (MySQL, SSH, FileBrowser, MCP, Redis, Kubernetes, Git repositories, Jenkins).
- `app/core/`: storage migrations, authorization, execution, and security infrastructure.
- `app/main.py`, `app/cli.py`: HTTP/MCP entry points and maintenance commands.
- `web/src/`: Vue admin UI; build output goes to `static/` and is not committed.
- `tests/`: API, isolation, migration, and protocol regression tests.

See [SECURITY.md](SECURITY.md) for the security boundary and vulnerability reporting, and [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## Who's Using It?

If your company or team runs this gateway in production, please [register your usage](https://github.com/SoWhatI/mcp-asset-gateway/issues/new?template=used_by.yml). Verified cases will be showcased here.

## Star History

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=SoWhatI/mcp-asset-gateway&type=Date&theme=dark" />
  <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=SoWhatI/mcp-asset-gateway&type=Date" />
  <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=SoWhatI/mcp-asset-gateway&type=Date" />
</picture>

## License

[MIT](LICENSE)
