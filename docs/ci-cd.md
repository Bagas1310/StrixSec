# CI / CD — StrixSec

StrixSec uses a single GitHub Actions workflow (`.github/workflows/ci.yml`) that runs
on every push and pull request. It contains two jobs.

## Jobs

### 1. `test`

Runs the Python test suite and quality gates on **Python 3.11 and 3.12** (matrix).

| Step | Command |
|------|---------|
| Checkout | `actions/checkout@v4` |
| Setup Python | `actions/setup-python@v5` |
| Install deps | `pip install .[dev]` |
| Lint | `ruff check .` |
| Format | `ruff format --check .` |
| Tests | `pytest -v` |

- Does **not** require Docker.
- Fails the workflow if any step fails.

### 2. `docker` (build verification)

Depends on `test` passing. Runs **only a build + smoke test** — it never pushes an image
and requires no registry credentials.

| Step | Action |
|------|--------|
| Build image | `docker build -t strixsec:ci .` |
| Smoke test | `docker run --rm strixsec:ci version`<br>`docker run --rm strixsec:ci --help`<br>`docker run --rm strixsec:ci report generate --help` |
| No-DB check | Asserts `/app/.strixsec.db` and `/data/.strixsec.db` are absent from the image |

## Secrets / Supply chain

- `.dockerignore` blocks `.env`, `.strixsec.db`, `.strixsec_scope.json` from the image.
- No secrets are committed to the repository.
- Dependencies are version-floored in `pyproject.toml` (`>=`). For production, consider
  generating a deterministic lockfile (`pip freeze > requirements.lock`) — not included by default.

## Development workflow

```bash
# 1. Make your changes
# 2. Run the same checks locally
.venv/scripts/ruff check .
.venv/scripts/ruff format --check .
.venv/scripts/pytest -v
# 3. (Optional) Build & smoke-test the container locally
docker build -t strixsec .
docker run --rm strixsec --help
# 4. Push a branch and open a PR — CI runs automatically
```

## Local Docker build

See [docs/docker.md](docker.md) for full instructions.
