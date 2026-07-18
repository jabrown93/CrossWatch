# Codebase Structure

## Core Sections (Required)

### 1) Top-Level Map

| Path | Purpose | Evidence |
|------|---------|----------|
| `crosswatch.py` | Main FastAPI application module and process entry point: builds `app = FastAPI()`, wires routers/services, defines `main()` and the `uvicorn.run()` call | crosswatch.py:29-77 (imports), :393 (`app = FastAPI()`), :1210-1281 (`main`, `__main__`) |
| `api/` | FastAPI route handlers, one module per feature area (`*API.py`); `api/__init__.py::register()` mounts every router onto the app | api/__init__.py:1-113; 26 files, e.g. authenticationAPI.py, syncAPI.py, scrobbleAPI.py, mobileAPI.py |
| `cw_platform/` | Core sync engine/platform: config loading (`config_base.py`), the `orchestrator` package (sync logic), ID mapping, metadata resolution, provider instantiation, TLS helpers, URL/SSRF validation | cw_platform/config_base.py, cw_platform/orchestrator/facade.py, cw_platform/id_map.py, cw_platform/tls.py, cw_platform/url_validation.py |
| `cw_platform/orchestrator/` (directory) | The actual orchestrator implementation package — `facade.py::Orchestrator`, `_pairs_oneway.py`, `_pairs_twoway.py`, `_snapshots.py`, `_planner.py`, `_applier.py`, `_state_store.py`, `_tombstones.py`, etc. | cw_platform/orchestrator/__init__.py (25 files in directory) |
| `cw_platform/orchestrator.py` (file) | **Not** the implementation — a 5-line dead-code shim that attempts to re-export from a same-named package. Python's import system always resolves `cw_platform.orchestrator` to the package (`orchestrator/__init__.py`), never to this file — see ARCHITECTURE.md and CONCERNS.md | cw_platform/orchestrator.py (full contents is a 5-line re-export attempt) |
| `providers/` | Provider integrations, split into `auth/` (OAuth/token flows, `_auth_*.py`), `sync/` (`_mod_*.py` dispatch files + one subdirectory per provider with feature handlers), `scrobble/` (real-time watch-tracking dispatcher+sinks), `webhooks/` (Plex/Emby/Jellyfin webhook receivers), `metadata/` (metadata enrichment) | providers/auth/ (10 `_auth_*.py` + `_auth_base.py`), providers/sync/ (11 `_mod_*.py` + per-provider dirs: plex, simkl, trakt, jellyfin, emby, mdblist, publicmetadb, crosswatch, tautulli, anilist, tmdb), providers/scrobble/, providers/webhooks/, providers/metadata/ |
| `services/` | Higher-level application services above the raw sync engine: analyzer, editor, export, scheduling, statistics, watchlist, backups, activity, dashboard widgets, playback progress. `services/__init__.py::register()` wires each module's own FastAPI routes onto the app — a separate registration path from `api/__init__.py::register()` | services/__init__.py:1-25, services/analyzer.py, services/scheduling.py, services/statistics.py |
| `ui_frontend.py` | Registers static asset mounting (`/assets`) and the single-page UI root/favicons/manifest/service-worker for the frontend | ui_frontend.py:1-60 |
| `assets/` | Frontend static files: hand-written vanilla JS (`assets/js/*.js`, `assets/helpers/*.js` — no bundler), one large `crosswatch.css`, PWA manifest/service-worker, fonts, images, themes | assets/js/ (24 files), assets/helpers/ (19 files), assets/manifest.webmanifest, assets/sw.js |
| `docker/` | Container-runtime maintenance script: `run-sync.py`, intended to run all configured sync pairs via the `Orchestrator` from inside a running container (replaces a former shell entrypoint since the runtime image is shell-less). Currently broken — see CONCERNS.md | docker/run-sync.py:1-36 |
| `tests/` | Pytest suite (~30 `test_*.py` files) + shared fixtures (`conftest.py`, sets `CONFIG_BASE` to a tmp path) | tests/conftest.py:1-17 |
| `providers/tests/` | A second, provider-scoped test tree with its own `pytest.ini` (separate from top-level `tests/`) — see TESTING.md | providers/tests/, providers/pytest.ini |
| `docs/` | GitHub Pages source (Jekyll `_config.yml`, `CNAME`, `index.md` that includes README.md) plus a `docs/codebase/` subfolder (this documentation set) | docs/_config.yml, docs/index.md, docs/CNAME |
| `android-companion/` | Separate Android companion app: Kotlin-DSL Gradle build scripts, but the app source itself is **Java**, not Kotlin (`MainActivity.java`, `QrScanActivity.java`); `app.crosswatch.companion`, minSdk 26 / targetSdk 36 | android-companion/build.gradle.kts, android-companion/settings.gradle.kts, android-companion/app/src/main/java/app/crosswatch/companion/ |
| `.github/workflows/` | CI (`ci.yml`: pytest on push/PR, Python 3.14 matrix), `release.yml` (semantic-release-driven Docker release on push to main/beta), `dev-image.yml` (manual multi-arch dev image build) | .github/workflows/ci.yml, release.yml, dev-image.yml |
| `_logging.py` | Repo-root structured logging module (color support), imported as `from _logging import log as LOG` throughout | crosswatch.py:44; _logging.py |
| `config.json`, `.cw_state/`, `sync_reports/`, `cache/`, `config/` | Local runtime/state artifacts in this working copy (the default `CONFIG_BASE` target when not overridden and not running inside `/app`) — instance data, not source | cw_platform/config_base.py:33-36 |

**Documented-vs-actual discrepancy:** CLAUDE.md (checked into the repo) describes a top-level `scripts/` directory containing `*_cleanup.py` maintenance scripts per provider. **No such directory exists** in the actual repo tree. The only maintenance script actually present is `docker/run-sync.py`. `[ASK USER]` — see CONCERNS.md.

### 2) Entry Points

- Main runtime entry: `crosswatch.py`, function `main(host="0.0.0.0", port=8787)` at crosswatch.py:1210, guarded by `if __name__ == "__main__": main()` at crosswatch.py:1281. Calls `uvicorn.run(app, **uv_args)` (crosswatch.py:1278) against the module-level `app = FastAPI()` (crosswatch.py:393).
- Container entry: Dockerfile `ENTRYPOINT ["python", "-m", "crosswatch"]` — runs the same `main()`, always binding `0.0.0.0:8787` regardless of the `WEB_HOST`/`WEB_PORT` env vars set in the image (those vars are not read anywhere in the Python source — see STACK.md §5).
- Secondary entry point: `docker/run-sync.py` — standalone script intended to be invoked inside a running container (`docker exec crosswatch python /app/docker/run-sync.py`) to run all configured sync pairs once, independent of the web server. Currently broken at runtime — see CONCERNS.md. docker/run-sync.py:1-36
- No separate CLI/worker/cron entry points exist; scheduling is handled in-process by `services/scheduling.py::SyncScheduler`, instantiated inside `crosswatch.py` (not a separate process).
- How entry is selected: no argv parsing — `main()`'s `host`/`port` parameters are Python defaults only. CLAUDE.md documents an alternate call form (`python -c "from crosswatch import main; main(host=..., port=...)"`) for local overrides, but the shipped Docker entrypoint does not expose this.

### 3) Module Boundaries

| Boundary | What belongs here | What must not be here |
|----------|-------------------|------------------------|
| `api/` | Thin FastAPI route/request handling: parsing requests, calling into `cw_platform`/`services`/`providers`, shaping HTTP responses. Each file exports a `router` (APIRouter) or a `register(app, ...)` function consumed by `api/__init__.py` | Provider HTTP calls, sync diffing/state logic, direct file I/O against state.json — those live in `cw_platform/orchestrator/` and `services/` |
| `cw_platform/orchestrator/` | Sync algorithm itself: snapshotting, diff planning, applying add/remove, tombstones, conflict policy, telemetry (`facade.py::Orchestrator` is the sole public entry, per CLAUDE.md's `InventoryOps` protocol) | Provider-specific HTTP/auth details (belong in `providers/`); HTTP route handling (belongs in `api/`) |
| `providers/sync/_mod_*.py` + `providers/sync/<provider>/` | Per-provider implementation of the `snapshot`/`add`/`remove` interface consumed by the orchestrator via `cw_platform/modules_registry.py`'s `MODULES["SYNC"]` map or `cw_platform/orchestrator/_providers.py`'s dynamic discovery | Cross-provider diff/merge logic (belongs in orchestrator); UI/route concerns |
| `providers/auth/_auth_*.py` | OAuth/token/device-code flows and credential storage per provider | Sync/watchlist business logic |
| `services/` | Cross-cutting application features above the orchestrator but not pure HTTP routing (analyzer, scheduler, exporter, statistics) — several modules register their own routes directly via `services/__init__.py::register()` | Low-level provider API calls (delegate to `providers/`) |
| `assets/` | Static frontend: vanilla JS/CSS, no build step, no server-side templating logic | Python business logic; anything requiring a bundler/transpiler (none is configured) |
| `android-companion/` | Fully separate Java/Gradle Android app — a companion client, not part of the Python backend's import graph | Any Python imports; not registered in `cw_platform/modules_registry.py` or `api/__init__.py` |

### 4) Naming and Organization Rules

- File naming pattern:
  - API route modules: `<feature>API.py`, e.g. `api/syncAPI.py`, `api/scrobbleAPI.py`, `api/mobileAPI.py`, `api/versionAPI.py` — confirmed consistent across all 26 files in `api/`.
  - Sync provider dispatch modules: `_mod_<PROVIDER>.py`, all-caps provider name, e.g. `providers/sync/_mod_TRAKT.py`, `_mod_PLEX.py`, `_mod_TAUTULLI.py`.
  - Auth provider modules: `_auth_<PROVIDER>.py`, same pattern, e.g. `providers/auth/_auth_TRAKT.py`, `_auth_PLEX.py`.
  - Internal orchestrator submodules are single-underscore-prefixed (`_applier.py`, `_snapshots.py`, `_planner.py`, `_pairs_oneway.py`, ...), signaling "not part of the public orchestrator API" — only `facade.py` is the public surface.
  - Per-provider sync detail lives in a matching lowercase subdirectory, e.g. `providers/sync/trakt/`, imported by `_mod_TRAKT.py` (`from .trakt._common import ...`).
  - Every source file opens with a `# /path/to/file.py` header comment plus a one-line description — a consistent repo-wide convention (crosswatch.py:1-3, providers/sync/_mod_TRAKT.py:1-3).
  - Test files: `tests/test_<subject>.py`, matched by `pytest.ini`'s `python_files = test_*.py`.
- Directory organization pattern: primarily **layered** (api/ = HTTP layer, cw_platform/ = engine layer, services/ = application-service layer, providers/ = integration layer), with `providers/` further split by **feature-within-integration** (auth vs sync vs scrobble vs webhooks vs metadata) and then by **provider** (plex/, trakt/, simkl/, ...) as a third-level domain split.
- Import aliasing or path conventions: no `src/`-style rooting or import aliases — everything imports as a top-level package relative to the repo root, enabled by `PYTHONPATH=/app` in Docker and `sys.path.insert(0, str(REPO_ROOT))` in `tests/conftest.py:9-11` for local test runs. Dynamic provider module loading goes through `cw_platform/modules_registry.py`'s `MODULES` dict plus `importlib.import_module`, so new providers are registered by adding an entry there (per CLAUDE.md's "Adding a New Provider" steps) — though see CONCERNS.md for the dual-registry drift risk this creates.

### 5) Evidence

- api/__init__.py (router registration source of truth)
- services/__init__.py (parallel, separate route-registration path)
- crosswatch.py (entry point, app construction, main())
- cw_platform/orchestrator/__init__.py and cw_platform/orchestrator.py (the file/dir duplication)
- cw_platform/modules_registry.py (provider module registry — naming-to-import-path mapping)
- providers/sync/_mod_TRAKT.py, providers/auth/_auth_TRAKT.py (naming convention exemplars)
- docker/run-sync.py (secondary entry point)
- tests/conftest.py (test path setup)

## Extended Sections (Optional)

Not populated — core sections are sufficient for current documentation needs.
