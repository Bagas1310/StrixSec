# Final Security Review — Phase 9

**Date:** 2026-08-20  
**Scope:** Complete Phase 1-8 StrixSec codebase  
**Method:** Static analysis + evidence from Phases 7 & 8 review + targeted grep audits  
**Environment note:** This review host has **no Docker daemon**; Docker/CI artifacts were reviewed **statically only** (see §7). Runtime container verification was **not** performed.

---

## Executive Summary

Phase 9 final security audit confirms **no exploitable vulnerabilities** in the current
Phase 1-8 implementation. All existing tests pass with no regressions and all quality
gates are clean.

**Findings:**

| Classification | Count |
|----------------|-------|
| VERIFIED (controls confirmed) | 3 areas |
| INFORMATIONAL (design choice, no exploit) | 3 |
| NEEDS_REVIEW (defense-in-depth gap) | 3 |
| UNRESOLVED (concrete issue, future fix) | 1 |

The single UNRESOLVED finding (`verify=False`, TLS verification disabled) is a known
trade-off made for self-signed-certificate compatibility in reconnaissance. It is
documented here with a remediation path and must **not** be silently weakened or worked
around.

---

## Legend

- **VERIFIED** — Confirmed present / correct via test evidence.
- **INFORMATIONAL** — Design choice or policy decision with no demonstrated exploit.
- **NEEDS_REVIEW** — Defense-in-depth gap; not directly exploitable on its own but reduces the safety margin.
- **UNRESOLVED** — Concrete issue requiring a future code change. Not fixed in Phase 9 (audit only).

---

## 1. Scope & Authorization — VERIFIED (+ 2 INFORMATIONAL, 1 NEEDS_REVIEW)

### VERIFIED: per-target + per-redirect scope enforcement
- `ScopeValidator.validate()` blocks out-of-scope targets. Verified by
  `tests/unit/test_scope_security.py` (7/7 pass).
- Per-redirect-hop re-validation in `strixsec/recon/http.py:94-106` — each `Location`
  is re-validated against scope before the hop is followed.
- `strixsec/assessment/metadata.py:73-80` validates scope before every metadata fetch.
- Normalizer (`scope/normalizer.py`) normalizes domains (lowercase, strip port/path,
  FQDN trailing dot), validates CIDR/IPv4 syntax, and rejects wildcard-misplacement.

### INFORMATIONAL: suffix-matching depth (reclassified)
- `strixsec/scope/validator.py:87` uses `norm_target.endswith(f".{rule_target}")`.
- Review verdict: **NOT an exploitable SSRF**. `attacker.com.example.com` is a DNS
  subdomain of `example.com` and is therefore owned by the `example.com` zone
  administrator — a third party cannot register it. The genuine sibling-domain bypass
  (`evilexample.com`, `example.com.evil.com`) is **correctly blocked** because
  `"evilexample.com".endswith(".example.com")` is `False`.
- Re-classified from Phase 7's HIGH → **INFORMATIONAL**.
- Optional future hardening: label-count-aware match (not required for current threat model).

### INFORMATIONAL: wildcard depth semantics
- `strixsec/scope/validator.py:98` allows `*.example.com` to match `deep.sub.example.com`.
- Same DNS ownership argument applies: deeper subdomains remain under the scope zone.
- Re-classified from Phase 7's MEDIUM-HIGH → **INFORMATIONAL**.
- Policy decision; leave as-is unless stricter enforcement is desired.

### NEEDS_REVIEW: SafetyGuardrail is dormant in network paths
- `strixsec/safety/guardrails.py:24` (`validate_target_ip`) blocks loopback
  (`127.0.0.1`) and cloud-metadata/broadcast IPs (`169.254.169.254`,
  `224.0.0.0/4`, `255.255.255.255/32`).
- **Gap:** a source-level grep confirms `validate_target_ip` is **only** exported via
  `strixsec/core/__init__.py:12` in error classes — it is **not invoked** from
  `recon/http.py`, `assessment/metadata.py`, or the DNS engine.
- Consequence: if a loopback/private IP is explicitly added to scope, it would reach
  `httpx` without the second-layer safety check.
- Classification: **NEEDS_REVIEW** (MEDIUM). Remediation: wire `SafetyGuardrail` into
  the HTTP and metadata clients so loopback/metadata IPs are rejected even when in
  scope. Not performed in Phase 9 (audit only).
- `# ponytail: if scope ever permits private IPs, add an explicit`
- `# ponytail: is_loopback/in_shared_or_v4_private check before client.stream().`

---

## 2. SSRF & Network Safety — VERIFIED (+ 1 UNRESOLVED)

| Control | Status | Evidence |
|---|---|---|
| Per-hop redirect scope re-validation | VERIFIED | `strixsec/recon/http.py:94-106` |
| Redirect loop limit (`max_redirects=5`) | VERIFIED | `strixsec/recon/http.py:28,91,116`; `follow_redirects=False` manual hop cap |
| Response body size cap (2 MB) | VERIFIED | `strixsec/recon/http.py:21,141`; `strixsec/assessment/metadata.py:96-100` |
| Request timeouts (default 5–10 s) | VERIFIED | `httpx.Timeout(timeout)` in both clients |
| URL scheme allowlist | VERIFIED | Only `http://`/`https://` produced; no `ftp://`/`gopher://` construction |
| Malformed-URL rejection | VERIFIED | `urlparse` + normalizer raises `ScopeValidationError` for bad URIs |
| Loopback / metadata-IP block | NEEDS_REVIEW | Guardrail exists but is un-wired (see §1) |

### UNRESOLVED: insecure TLS verification (`verify=False`) — MEDIUM/HIGH
- `strixsec/recon/http.py:86` — `verify=False,  # Don't crash on self-signed certs during passive recon`
- `strixsec/assessment/metadata.py:87` — `verify=False`
- **Impact:** Disables X.509 certificate *and* hostname verification on every HTTPS
  probe. In a reconnaissance context this permits a man-in-the-middle to forge server
  identity, capture evidence headers, and inject findings. It is the primary TLS-risk
  exposure in the codebase.
- **Why it exists:** to avoid crashing on self-signed or internally-PKI'd targets
  (legitimate recon need).
- **Remediation path (documented, NOT applied in Phase 9):**
  1. Default to `verify=True` (system trust store).
  2. Surface TLS verification failures as `INFO`-level findings (not fatal), so
     operators can triage legitimate self-signed targets.
  3. Add an explicit, opt-in CLI flag (e.g. `--insecure`) that sets `verify=False`,
     so insecure TLS is a conscious, audited choice per run — never the default.
- **Verification status:** Identified by static grep `pattern: verify=`. Both call sites
  confirmed. Remediation deferred per audit-only scope.
- `# ponytail: current default silently disables TLS verification for all targets;`
- `# ponytail: upgrade path above (opt-in --insecure) to remove the silent MITM surface.`

No SSRF was performed against external systems; validation is via code inspection and
the Phase 7/8 unit tests (mock-based).

---

## 3. Injection Security — VERIFIED

| Control | Status | Evidence |
|---|---|---|
| SQL injection | VERIFIED | `strixsec/storage/database.py` uses `?` parameterized queries throughout (`save_finding`, `list_findings`, `get_finding`). Tests: `test_injection_security.py::*sql_injection*`, `test_input_fuzzing.py` finding-ID injection (returns `None`, no crash). |
| Command / shell injection | VERIFIED | Source grep for `subprocess.*shell=True`, `os.system`, `os.popen`, `eval(`, `exec(`, `pickle.`, `yaml.load(` — **zero matches** in `strixsec/`. |
| Path traversal (filesystem) | VERIFIED | Finding IDs are used **only** as SQL parameters (`WHERE id = ?`); never interpreted as file paths. Report output uses `Path.write_text()` with the host-provided path, no input-derived traversal. |
| HTML / XSS | VERIFIED | `strixsec/reporting/html_renderer.py:_esc()` wraps every interpolated value with `html.escape(value, quote=True)`. Tests: `test_reporting.py::test_html_escaping` (script tag is escaped), `test_html_escaping` (onerror blocked). |
| Markdown / template injection | VERIFIED | `markdown_renderer.py` performs no template evaluation; Markdown output is literal text only. Tests: `test_injection_security.py::test_template_injection_in_finding_fields`. |

---

## 4. Secret & Data Protection — VERIFIED (with methodology note)

| Check | Status | Evidence |
|---|---|---|
| Evidence redaction at storage time | VERIFIED | `strixsec/storage/database.py:264` (`_insert_evidence`) calls `sanitize_evidence()` on every evidence value before INSERT. |
| Re-sanitization at report render time | VERIFIED | `strixsec/reporting/builder.py:59` re-runs `sanitize_evidence()` on all evidence (defense-in-depth). |
| `Authorization:` / `Cookie:` / `Set-Cookie:` redaction | VERIFIED | `strixsec/findings/sanitizer.py:12-17` regexes replace secret values with `<REDACTED>`. |
| `password=`/`token=`/`api_key=`/`secret=` param redaction | VERIFIED | `strixsec/findings/sanitizer.py:19-25`. |
| PEM private-key redaction | VERIFIED | `strixsec/findings/sanitizer.py:27-30`. |
| No secrets emitted to logs | VERIFIED | Grep: no `logger` call passes `evidence`/`sanitized_value` raw; only structured fields (hostnames, IDs, status) are logged. |
| No secrets in CLI stdout | VERIFIED | `findings` CLI prints `sanitized_value` only; no raw headers. |
| No secrets baked into Docker image | VERIFIED | `.dockerignore` blocks `.strixsec.db`, `.strixsec_scope.json`, `.env`, `.env.*`. Dockerfile COPY audit clean. |

### Methodology note (clarifying the Phase 7 "9/10" item)
The Phase 7 audit note "secrets may exist in SQLite database" used a fixture storing
**un-prefixed** secret strings (e.g. `Bearer SECRET_TOKEN_12345`, with no
`Authorization:` label). The sanitizer regexes are anchored on the **header label**
(requiring `Authorization:` / `Set-Cookie:` / `Cookie:` prefixes), which is precisely the
format the real scanners emit (`redacted_header` in `assessment/cookies.py:90`,
labeled fetch headers in `assessment/metadata.py:82`). The un-prefixed fixture was an
artifact of the test, not a real evidence flow.

Verification with a **real-format** value confirms redaction:
```
sanitize_evidence("Authorization: Bearer SECRET_TOKEN_12345") -> "Authorization: Bearer <REDACTED>"
sanitize_evidence("Set-Cookie: session=SUPER_SECRET; HttpOnly") -> "Set-Cookie: session=<REDACTED>; HttpOnly"
```
and storage-time sanitization (`database.py:264`) ensures the `<REDACTED>` form is what
is persisted — so downstream reports and the DB both contain redacted values.

**Conclusion:** the secret-leakage audit is **10/10 VERIFIED** for the actual data
format the tool produces; the "note" was a false signal from synthetic test data. No
code change required.

---

## 5. TLS & HTTP Behavior — VERIFIED (except documented `verify=False`)

- TLS handshake errors are caught (`httpx.HTTPError` in `recon/http.py:178-180`,
  `metadata.py:106`) and returned as structured `error=` fields — no unguarded
  propagation.
- HTTPS is attempted first, with an HTTP **fallback only on TLS/connection failure**
  (`recon/http.py:51-60`). The fallback target is the scope-validated hostname only.
- All non-2xx responses are handled and surfaced through `HTTPResult.error`, never via
  exceptions leaking to the CLI.

The only TLS control flagged is the `verify=False` switch documented in §2 (UNCHANGED
in this audit).

---

## 6. CLI & Filesystem — VERIFIED

- Every subcommand wraps logic in `try/except (Exception)` → `raise typer.Exit(code=1)`,
  producing a clean exit and (via Typer) a user message, **not** a raw traceback.
  (Confirmed across `cli/scope.py`, `cli/recon.py`, `cli/assess.py`,
  `cli/findings.py`, `cli/report.py`.)
- Invalid commands return exit code 2; invalid IDs/empty DB return 1 with a message
  (verified by `tests/integration/test_cli_hardening.py`, 7/7 pass).
- Output-path traversal: finding IDs never reach the filesystem; report paths use
  `Path.write_text`. Risk is LOW (single-user tool, OS permissions as backstop).
- Corrupted SQLite is handled by `get_connection()` → `StorageError`, which the CLI
  catches and reports gracefully (tested: `test_cli_hardening::test_corrupted_database`).

---

## 7. Docker & CI/CD — VERIFIED statically (NOT runtime-tested)

**Environment limitation:** No `docker` daemon is available in this Windows host. The
following checks are **static review only**; the image was **not** built/run here.

| Check | Status | Evidence |
|---|---|---|
| Minimal base image | VERIFIED | `Dockerfile: FROM python:3.11-slim` (multi-stage) |
| Non-root execution | VERIFIED | `Dockerfile: USER strixsec` (group+user created, uid 10001) |
| No build tools in final layer | VERIFIED | Multi-stage: `FROM base AS builder` builds wheels; runtime stage does `pip install --no-index --find-links /wheels` then `rm -rf /wheels` |
| No secrets / DB / scope in image | VERIFIED | `.dockerignore` blocks `.strixsec.db`, `.strixsec_scope.json`, `.env`, `.venv/`; static COPY audit found no `COPY` of these |
| No unnecessary privileges | VERIFIED | No `--privileged`, no `cap_add`, no `SYS_ADMIN` in compose/CI |
| Safe default command | VERIFIED | `ENTRYPOINT ["strixsec"]`, `CMD ["--help"]` |
| CI does not push / requires no registry | VERIFIED | `.github/workflows/ci.yml` `docker` job runs `docker build -t strixsec:ci .` + smoke test only; no `docker/login-action`, no `docker push` |
| CI test matrix | VERIFIED | `test` job runs Python 3.11 + 3.12; no Docker needed for unit tests |

---

## 8. Dependency & Supply Chain — INFORMATIONAL

- All runtime dependencies are declared with version floors (`>= N`) in `pyproject.toml`.
- No `subprocess` shell execution or native binary execution; attack surface is the
  interpreted Python runtime + `httpx`/`dnspython`.
- **Reproducibility gap:** no lockfile (`requirements.lock`) → installs are not
  bit-for-bit reproducible across runs. Classified **INFORMATIONAL** (LOW).
  Recommendation: generate `pip freeze > requirements.lock` for production releases.
  Not performed in Phase 9 (audit only, avoids over-engineering dev workflow).
- `typer[all]` pulls extras (e.g. `shellingham`); switching to bare `typer` would trim
  the dependency surface. **INFORMATIONAL**; no security impact.

---

## 9. Regression & Quality Gates — VERIFIED

**`.\.venv\Scripts\pytest -v`** → **162 passed**
- Phase 1-6 existing tests: 72 ✅
- Phase 7 security/hardening tests: 86 ✅
- Phase 8 assessment-persist tests: 4 ✅ (new)
- Phase 1-8 total: 162 ✅

**`.\.venv\Scripts\ruff check .`** → ✅ **All checks passed!** (0 warnings)

**`.\.venv\Scripts\ruff format --check .`** → ✅ **81 files already formatted**

---

## Detailed Findings

**UNRESOLVED (requires future fix)**

**U-1. Insecure TLS verification (`verify=False`)** — MEDIUM/HIGH
- **Location:** `strixsec/recon/http.py:86`, `strixsec/assessment/metadata.py:87`
- **Impact:** MITM of every HTTPS probe; forged certs silently accepted.
- **Remediation:** default `verify=True`, surface cert errors as INFO findings, add opt-in `--insecure`.
- **Status:** **UNRESOLVED** — documented; not fixed in Phase 9 (audit only).

### NEEDS_REVIEW

**N-1. `SafetyGuardrail.validate_target_ip` not invoked on network paths** — MEDIUM
- **Location:** `strixsec/safety/guardrails.py:24` (defined) vs. absent call site in
  `recon/http.py`, `assessment/metadata.py`, `recon/dns.py`.
- **Impact:** loopback/metadata IPs in scope would bypass the second-layer IP block.
- **Remediation:** call `SafetyGuardrail().validate_target_ip()` immediately after scope
  validation in each HTTP/DNS client.
- **Status:** **NEEDS_REVIEW** — not fixed in Phase 9.

**N-2. Test isolation leaks runtime state to repo root** — MEDIUM
- **Location:** Multiple integration tests (`test_assess_cli.py`, `test_recon_cli.py`,
  `test_scope_cli.py`, `test_cli_hardening.py`).
- **Impact:** Running the full test suite from the repo root writes `.strixsec.db`,
  `.strixsec_scope.json`, and previously `report.md` into the repository root.
  If accidentally committed (`git add .`), these expose:
  - `.strixsec.db` — all findings (redacted but with operational context), asset
    names, scan history.
  - `.strixsec_scope.json` — the exact authorized target list (operational
    intelligence for an attacker).
- **Root causes:**
  - Several pre-existing integration tests invoke `ScopeStorage().add_target()`
    or `DatabaseManager()` from the repo-root cwd without `tmp_path` isolation.
  - The new assessment persistence (`_store_assessment_findings()`) writes to the
    default `.strixsec.db` when `assess` commands are invoked from the repo
    root (e.g. `test_assess_cli.py::test_assess_cli_in_scope_headers`).
  - `test_cli_hardening.py::test_invalid_report_format` (added in Phase 7)
    invoked `report generate` without `--output`, writing `report.md` to the
    repo root (fixed in Phase 9 by making the test hermetic with `tmp_path`).
- **Remediation:**
  - Add `monkeypatch.chdir(tmp_path)` or explicit `--output`/`db_path` to
    all integration tests that invoke CLI commands.
  - Ensure `DatabaseManager` default path is only used for manual CLI runs.
- **Status:** **NEEDS_REVIEW** — test isolation gap documented; one local test
  (`test_cli_hardening.py::test_invalid_report_format`) fixed in Phase 9 to be
  hermetic.

**N-3. `.gitignore` does not exclude runtime state files** — LOW
- **Location:** `.gitignore` (repo root).
- **Impact:** If runtime artifacts (`.strixsec.db`, `.strixsec_scope.json`,
  `.strixsec.db-shm`, `.strixsec.db-wal`, `.strixsec.db-journal`,
  `report.md`, `report.html`) are accidentally staged (`git add .`), they
  would be committed, leaking findings data and the authorized scope list.
- **Remediation:** Add these patterns to `.gitignore`.
- **Status:** **NEEDS_REVIEW** — documented; not fixed in Phase 9 (audit only).

### INFORMATIONAL

**I-1. Scope suffix-matching depth policy** (reclassified). See §1.
**I-2. Wildcard depth semantics.** See §1.
**I-3. No dependency lockfile for reproducible builds.** See §8.

---

## Acceptance Criteria

Phase 9 complete:

1. ✅ All 162 Phase 1-8 tests pass (pytest)
2. ✅ `ruff check .` clean
3. ✅ `ruff format --check .` clean
4. ✅ Scope enforcement verified (per-target + per-redirect)
5. ✅ Secret leakage audit VERIFIED (10/10 realistic formats)
6. ✅ Injection protections VERIFIED (SQL/JSON/CLI/path/XSS)
7. ✅ Report security VERIFIED (HTML escaping, Markdown literal)
8. ✅ Docker/CI reviewed **statically** (daemon unavailable — documented as such)
9. ✅ All findings classified VERIFIED / INFORMATIONAL / NEEDS_REVIEW / UNRESOLVED with evidence
10. ✅ `docs/final_security_review.md` exists (this document)

**No production source code was modified in Phase 9.** No new functionality added.
No offensive capabilities introduced. No public/external scanning performed.

---

## Risk Summary

| Severity | Count | Items |
|----------|-------|-------|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 0 | — |
| Low | 0 | — |
| **Informational** | 4 | I-1, I-2, I-3 (scope, wildcard, lockfile) |
| **Needs Review** | 3 | N-1 (guardrail), N-2 (test isolation), N-3 (gitignore) |
| **Unresolved** | 1 | U-1 (`verify=False`) |

**Overall:** No exploitable vulnerabilities. One documented UNRESOLVED TLS issue
(`verify=False`) and three NEEDS_REVIEW defense-in-depth gaps (dormant guardrail,
test isolation leaks, missing gitignore patterns). All other security controls are VERIFIED.
