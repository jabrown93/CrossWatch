# Technology Stack

## Core Sections (Required)

### 1) Runtime Summary

| Area | Value | Evidence |
|------|-------|----------|
| Primary language | Python | requirements.txt; crosswatch.py; cw_platform/, api/, providers/, services/ are all `.py` |
| Runtime + version | CPython 3.14 (3.14.6 in Docker image; CI matrix pins "3.14") | Dockerfile:8 (`FROM dhi.io/python:3.14.6-alpine3.24-dev AS builder`), Dockerfile:34 (runtime stage `FROM dhi.io/python:3.14.6-alpine3.24`), .github/workflows/ci.yml:23 (`python-version: ["3.14"]`). No `pyproject.toml`/`setup.py`/`setup.cfg` exists in repo root, so there is no `python_requires` declaration outside Docker/CI. |
| Package manager | pip, driven by plain `requirements.txt` files (no lockfile, no Poetry/pipenv/uv) | requirements.txt, requirements-dev.txt, Dockerfile:26-30 (`pip install -r requirements.txt` into a venv) |
| Module/build system | None (no packaging config) for Python — it runs as a flat script tree via `PYTHONPATH=/app`; for the JS frontend there is no bundler (vanilla JS assets served as static files); for Android, Gradle (Kotlin DSL build scripts, Java app source) | Dockerfile:47 (`ENV PYTHONPATH=/app`), package.json (only devDependencies, no build script), android-companion/build.gradle.kts, android-companion/settings.gradle.kts |

### 2) Production Frameworks and Dependencies

List only high-impact production dependencies (frameworks, data, transport, auth).

| Dependency | Version | Role in system | Evidence |
|------------|---------|----------------|----------|
| fastapi | unpinned (no version specified) | Web framework; `app = FastAPI()` in crosswatch.py:393, routers mounted via `api/__init__.py::register()` | requirements.txt:1, crosswatch.py:393 |
| uvicorn | unpinned | ASGI server that runs the app (`uvicorn.run(app, **uv_args)`) | requirements.txt:3, crosswatch.py:1278 |
| pydantic | unpinned | Data validation (FastAPI's schema layer) | requirements.txt:2 |
| requests | unpinned | Synchronous HTTP client used throughout provider modules | requirements.txt:4, e.g. providers/auth/_auth_TRAKT.py:12 |
| plexapi | unpinned | Plex Media Server API client library | requirements.txt:5 |
| websocket-client / websockets | unpinned | WebSocket clients, used by Plex/Emby/Jellyfin watchers for live scrobbling | requirements.txt:6-7 |
| python-multipart | unpinned | Multipart/form-data parsing support required by FastAPI for file/form uploads | requirements.txt:8 |
| cryptography | unpinned | Backing library for config-secret encryption (Fernet, `enc:v1:` prefix) and TLS cert handling | requirements.txt:10, cw_platform/config_base.py:42-45, cw_platform/tls.py |
| qrcode | unpinned | QR code generation, used in mobile-companion pairing flow | requirements.txt:11, api/mobileAPI.py |
| packaging | unpinned | Version-string comparison, used by versionAPI for update checks | requirements.txt:9, api/versionAPI.py |

**Gap:** `requirements.txt` pins no versions at all (bare package names) — actual resolved versions are whatever `pip install` picks at build/CI time. No lockfile exists. See CONCERNS.md for the reproducibility risk this creates.

### 3) Development Toolchain

| Tool | Purpose | Evidence |
|------|---------|----------|
| pytest (>=8.0) | Test runner | requirements-dev.txt:1, pytest.ini |
| pytest-cov (>=5.0) | Coverage reporting (declared but never invoked — see TESTING.md) | requirements-dev.txt:2 |
| responses (>=0.25) | HTTP mocking (declared but used in only one test file — see TESTING.md) | requirements-dev.txt:3 |
| httpx (>=0.27) | HTTP client used by FastAPI's `TestClient` | requirements-dev.txt:4 |
| eslint 10.7.0 | JS linting (declared as devDependency; **no config file found** — see gap below) | package.json |
| eslint-plugin-prettier 5.5.6 / eslint-config-prettier 10.1.8 | Integrates Prettier formatting rules into ESLint | package.json |
| prettier 3.9.5 | JS/CSS formatting (declared as devDependency; **no config file found**) | package.json |
| semantic-release (+ plugins: commit-analyzer, release-notes-generator, changelog, github, git) | Automated versioning/changelog/GitHub Release from Conventional Commits | .releaserc.js |
| GitHub Actions (`ci.yml`, `release.yml`, `dev-image.yml`) | CI test matrix, semantic-release-driven Docker release, on-demand dev image build | .github/workflows/ci.yml, .github/workflows/release.yml, .github/workflows/dev-image.yml |
| Renovate | Automated dependency updates (extends a shared org config) | renovate.json |

**Gap:** `package.json` declares eslint/prettier as devDependencies, but **no ESLint or Prettier config file** (`.eslintrc*`, `eslint.config.*`, `.prettierrc*`) exists anywhere in the repo. `npx eslint .` / `npx prettier --check .` (as documented in CLAUDE.md) would currently run against tool defaults only, or no-op. See CONCERNS.md.

### 4) Key Commands

```bash
# Install
pip install -r requirements.txt -r requirements-dev.txt   # .github/workflows/ci.yml:33-36
npm install                                                 # package.json (devDependencies only)

# Run (local)
python crosswatch.py                                        # crosswatch.py:1281 -> main(host="0.0.0.0", port=8787)

# Run (Docker)
docker build -t crosswatch .
docker run -d -p 8787:8787 -v crosswatch_config:/config -e TZ=Europe/Amsterdam crosswatch   # README.md:113-123
# ENTRYPOINT is fixed: ["python", "-m", "crosswatch"] (Dockerfile) — always binds 0.0.0.0:8787

# Test
pytest                                                        # pytest.ini: addopts = -q --disable-warnings --maxfail=1
pytest --cov                                                  # CLAUDE.md-documented; not run in CI (see TESTING.md)

# Lint (frontend only; no config file confirmed — see gap above)
npx eslint .
npx prettier --check .
```

### 5) Environment and Config

- Config sources: `CONFIG_BASE/config.json` (user config), `state.json`, `statistics.json`, `last_sync.json`, `tombstones.json` — all resolved relative to `cw_platform/config_base.py:28-40 CONFIG_BASE()`.
- Required/consumed env vars (verified in code):
  - `CONFIG_BASE` — overrides the config/state directory; falls back to `/config` if `/app` exists (i.e., inside the container image), else the repo root (cw_platform/config_base.py:29-36).
  - `APP_VERSION` — baked in at Docker build time, read via `os.getenv("APP_VERSION", "v0.9.25")` for the reported release version (api/versionAPI.py:22).
  - `CW_CONFIG_KEY` / `CROSSWATCH_CONFIG_KEY` — optional Fernet key for config-secret encryption (see INTEGRATIONS.md).
  - `CW_LOG_FORMAT`, `CW_LOG_COLOR`, `NO_COLOR` — logging output controls (`_logging.py`).
- Env vars set in the Dockerfile but **not referenced anywhere in the Python source**: `WEB_HOST`, `WEB_PORT`, `WEBINTERFACE`, `RUNTIME_DIR`. `main()` hardcodes `host="0.0.0.0", port=8787`. `[TODO]` — these look like vestigial/aspirational env vars from a removed shell entrypoint; see CONCERNS.md.
- `RELEASE_DEPS` — optional env var read by `.releaserc.js` to promote dependency-bump commits to a release (`.releaserc.js:16`).
- Deployment/runtime constraints: Runtime Docker image (`dhi.io/python:3.14.6-alpine3.24`, a Docker Hardened Image) is shell-less and runs as a fixed nonroot user — bind-mounted `/config` must be pre-chowned to the nonroot UID on the host. Container HEALTHCHECK is a pure-Python TCP probe of port 8787 (no `curl`/`wget` available). Per SECURITY.md, the app is explicitly designed for LAN/VPN-only use, not public internet exposure.

### 6) Evidence

- requirements.txt, requirements-dev.txt, package.json, pytest.ini
- Dockerfile, docker-compose.yml
- .github/workflows/ci.yml, .github/workflows/release.yml, .github/workflows/dev-image.yml
- .releaserc.js, renovate.json
- crosswatch.py (lines 1210-1281: `main()`, `uvicorn.run`)
- cw_platform/config_base.py (lines 28-40: `CONFIG_BASE()`)
- api/versionAPI.py (line 22: `CURRENT_VERSION`)
- android-companion/build.gradle.kts, android-companion/settings.gradle.kts, android-companion/app/build.gradle

## Extended Sections (Optional)

Not populated — core sections are sufficient for current documentation needs.
