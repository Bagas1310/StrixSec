# Docker Usage — StrixSec

StrixSec ships as a single CLI image. Docker is the easiest way to run it reproducibly
without Python/venv setup.

## Quick start (single run)

Build once:
```bash
docker build -t strixsec .
```

Run with your current directory mounted as workspace (so `.strixsec.db` /
`.strixsec_scope.json` persist on the host):
```bash
docker run --rm -v "$PWD:/data" -w /data strixsec scope add example.com
docker run --rm -v "$PWD:/data" -w /data strixsec recon dns example.com
docker run --rm -v "$PWD:/data" -w /data strixsec report generate -o report.md
```

## Inspect a built report outside the container
```bash
ls -la report.md
```

## Docker Compose (convenience)

`docker-compose.yml` mounts `./workspace` into the container's `/data` so state
persists between runs, and `./reports` into `/reports`:

```bash
docker compose run --rm strixsec scope add example.com
docker compose run --rm strixsec recon dns example.com
docker compose run --rm strixsec report generate -o /reports/report.md
```

Generated reports land in `./reports/` on the host.

### Override the default command

The service `command` defaults to `["--help"]`. Pass any StrixSec subcommand:
```bash
docker compose run --rm strixsec findings list
```

## Image properties

| Property       | Value              |
|----------------|--------------------|
| Base image     | `python:3.11-slim` |
| User           | `strixsec` (uid 10001, non-root) |
| Working dir    | `/data` (read-only `/app`) |
| Entry point    | `strixsec`         |
| Default CMD    | `["--help"]`       |
| Secrets copied | None (`.dockerignore` blocks `.env`, `.strixsec.db`, `.strixsec_scope.json`) |

## Troubleshooting

**`Permission denied` writing `/data/.strixsec.db`**
The bind-mounted folder must be writable by uid 10001. On Linux:
```bash
mkdir -p workspace && chmod 777 workspace
```
On macOS/Windows the default bind mount is writable by the mapped uid.

**Stale DB after changing code** — the image is read-only; remove the container and
rebuild:
```bash
docker build -t strixsec .
```

**No reports in `./reports/`** — the compose file mounts `./reports:/reports`. When using
`docker run` directly, mount the reports folder too:
```bash
docker run --rm -v "$PWD:/data" -v "$PWD/reports:/reports" -w /data strixsec report generate -o /reports/report.md
```
