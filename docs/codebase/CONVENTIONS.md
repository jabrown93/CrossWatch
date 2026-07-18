# Coding Conventions

## Core Sections (Required)

### 1) Naming Rules

| Item | Rule | Example | Evidence |
|------|------|---------|----------|
| Files (Python, provider modules) | `_auth_<PROVIDER>.py` / `_mod_<PROVIDER>.py` where `<PROVIDER>` is UPPERCASE; shared/base modules use a lowercase suffix instead (`_auth_base.py`, `_mod_common.py`) | `providers/auth/_auth_PLEX.py`, `providers/sync/_mod_SIMKL.py` | providers/auth/ (10 files, all `_auth_[A-Z]+\.py` except `_auth_base.py`); providers/sync/ (11 files, all `_mod_[A-Z]+\.py` except `_mod_common.py`, `_log.py`) |
| Files (API routers) | `<domain>API.py`, lowerCamel domain + literal `API` suffix | `api/syncAPI.py`, `api/configAPI.py` | api/ directory listing (26 files, all follow this pattern) |
| Files (orchestrator internals) | Leading-underscore module name signaling "private/internal", `snake_case` | `cw_platform/orchestrator/_pairs_oneway.py`, `_planner.py`, `_snapshots.py` | cw_platform/orchestrator/ (10 of 12 files underscore-prefixed; only `facade.py` and `__init__.py` are not) |
| Files (tests) | `tests/test_<subject>.py`, mirrors `pytest.ini`'s `python_files = test_*.py` | `tests/test_redact_config.py`, `tests/test_sync_provider_logging.py` | pytest.ini:3; tests/ directory listing |
| Functions/methods (Python) | `snake_case`; leading underscore = internal/module-private | `def redact_config(...)`, `def _redact_path(...)` | cw_platform/config_base.py:765,778 |
| Functions/variables (JS) | `camelCase`; files are non-module IIFEs, no class-based OOP observed | `const ensureStyle = (id, txt) => {...}`, `function bootEditor()`, `providerKey` | assets/js/main.js:6, assets/js/editor.js:404,734, assets/js/watchlist.js:47 |
| Types/interfaces (Python) | `PascalCase` for classes, dataclasses, and `Protocol` definitions | `class Orchestrator`, `class ConflictPolicy`, `class InventoryOps(Protocol)`, `class PlexAuth(AuthProvider)` | cw_platform/orchestrator/facade.py:49; cw_platform/orchestrator/_types.py:11,41; providers/auth/_auth_PLEX.py:40 |
| Constants/env vars | `UPPER_SNAKE_CASE`; env vars namespaced with `CW_` prefix | `CW_LOG_FORMAT`, `CW_DEBUG`, `CW_EMBY_HISTORY_PAGE_SIZE`, module const `PLEX_PIN_URL` | grep of `os.environ.get("CW_...")` across repo (30+ hits); providers/auth/_auth_PLEX.py:34-37 |
| Java (android-companion) | `PascalCase` classes, `UPPER_SNAKE_CASE` `static final` constants — standard Java convention | `class MainActivity extends Activity`, `private static final int REQ_SCAN_QR = 3701;` | android-companion/app/src/main/java/app/crosswatch/companion/MainActivity.java:57-58 |

**Note:** `android-companion` is often assumed to be Kotlin (its Gradle build scripts use the Kotlin DSL — `build.gradle.kts`), but the actual app source is **Java** — no `.kt` source files exist anywhere in the tree. Only `MainActivity.java` and `QrScanActivity.java` are present.

### 2) Formatting and Linting

- **Formatter: `[TODO]` — no config found.** `prettier` (3.9.5) is listed in `package.json` devDependencies, but no `.prettierrc*` or `prettier.config.*` file exists anywhere in the repo.
- **Linter: `[TODO]` — no config found.** `eslint` (10.7.0), `eslint-config-prettier`, `eslint-plugin-prettier` are listed as devDependencies, but no `eslint.config.*` or `.eslintrc*` file exists anywhere in the repo. `npx eslint .` would currently fail/no-op for lack of a config — see CONCERNS.md.
- **Python linter/formatter: none present.** No `pyproject.toml`, `setup.cfg`, `.flake8`, or `ruff.toml` found anywhere. Python code style is enforced only by convention/review, not tooling.
- Most relevant enforced rules: `[TODO]` — cannot be determined; no linter config exists to enforce any rules.
- Run commands (as documented in CLAUDE.md, unverifiable without config): `npx eslint .`, `npx prettier --check .`; Python tests via `pytest` (pytest.ini:1-3, addopts `-q --disable-warnings --maxfail=1`).

### 3) Import and Module Conventions

- Import grouping/order: Loosely layered but **not alphabetized/isort-enforced**: `from __future__ import annotations` first, then stdlib, then third-party (`requests`, `fastapi`), then internal/local imports (`cw_platform.*`, `api.*`, `providers.*`), sometimes under an explicit `# Internal imports` comment. Order varies file-to-file. Evidence: crosswatch.py:1-34, services/analyzer.py:1-19.
- Alias vs relative import policy: Python uses **absolute imports** rooted at repo root (e.g. `from cw_platform.config_base import ...`), with `tests/conftest.py:9-11` inserting `REPO_ROOT` onto `sys.path` to make this resolvable in tests. Within a provider package, relative imports (`from ._auth_base import ...`, `from ._log import log as cw_log`) are used for sibling private modules. No path aliasing observed. Evidence: providers/auth/_auth_PLEX.py:14-16, providers/sync/_mod_SIMKL.py:16-32.
- Public exports/barrel policy: Some modules declare `__all__` explicitly (e.g. api/syncAPI.py:19 — `__all__ = ["router", "_is_sync_running", "_load_state", "_find_state_path"]`; _logging.py:303), but this is not universal. JS has almost no ES module `import`/`export` — only `assets/js/modals.js` uses `type="module"`; every other script is a plain non-module `<script src=... defer>` tag registering onto the global `window.CW` namespace (ui_frontend.py:120-131).

### 4) Error and Logging Conventions

- Error strategy by layer: API route handlers predominantly raise `fastapi.HTTPException` with explicit `status_code`/`detail` for client-facing errors (api/editorAPI.py, api/authenticationAPI.py — used directly in 5 of 23 `api/*.py` files). Broader defensive `except Exception:` blocks are pervasive across almost every API module (e.g. api/syncAPI.py has 77 occurrences, api/authenticationAPI.py 67, api/scrobbleAPI.py 67) to keep individual endpoints from crashing the app; failures are frequently converted into structured `JSONResponse({"ok": False, "error": ...}, status_code=...)` payloads instead of exceptions (e.g. api/syncAPI.py:1730). No single, consistent error envelope shape is enforced across all endpoints.
- Logging style and required context fields: Central structured `Logger` class in `_logging.py:72-298` supports leveled logging (`debug/info/warn/error/success`), colorized text output, a `module` context tag, optional JSON-line sink (`enable_json`), and a `bind()/child()` pattern for adding context without mutating the parent logger (_logging.py:134-153). Level/color/format are controlled via env vars `CW_LOG_FORMAT`, `CW_LOG_COLOR`, `NO_COLOR`, and `runtime.debug`/`runtime.debug_mods` from `config.json`. Provider sync modules use a narrower `providers/sync/_log.py` logger keyed by `(provider, feature, level, message, **kv)`.
- Sensitive-data redaction rules: cw_platform/config_base.py:710-807 defines `_REDACT = "••••••••"` and a canonical `_SECRET_PATHS` list covering every provider's tokens/secrets/passwords/webhook secrets. `redact_config(cfg)` deep-copies the config and replaces truthy leaf values with `_REDACT`, additionally covering per-provider `instances` blocks, `app_auth.sessions[].token_hash`, and `security.webhook_ids`. Empty-string secrets are intentionally left untouched (verified by tests/test_redact_config.py:59-63). Fully covered by 7 dedicated test functions in tests/test_redact_config.py.

### 5) Testing Conventions

- Test file naming/location rule: All tests live flat in `tests/`, named `test_<subject>.py`, matching `pytest.ini`'s `python_files = test_*.py`. ~30 test files present.
- Fixture usage: `tests/conftest.py` defines one shared fixture, `config_base(tmp_path, monkeypatch)`, pointing `CONFIG_BASE` at a pytest `tmp_path` for isolation (tests/conftest.py:14-17). It also inserts `REPO_ROOT` into `sys.path` (tests/conftest.py:9-11).
- Mocking strategy norm: **`pytest`'s `monkeypatch` fixture is the dominant/default mocking approach**, used in 19-22 of ~30 test files. The `responses` library (declared in requirements-dev.txt as the intended approach per CLAUDE.md's "Testing Provider Code" section) and `unittest.mock` are each used in only **one** file, tests/test_version_api.py — the documented pattern is not actually followed elsewhere in the current suite.
- Coverage expectation: `[TODO]` — `pytest --cov` is documented as runnable in CLAUDE.md, but no coverage threshold, `.coveragerc`, or `[tool.coverage]` config exists. No enforced minimum coverage.

### 6) Evidence

- package.json (repo root) — lists eslint/prettier as devDependencies with no accompanying config file found anywhere in the tree
- pytest.ini (repo root) — only pytest config present; no Python lint/format config exists
- _logging.py — structured `Logger` implementation with color/JSON/context-binding support
- cw_platform/config_base.py:710-809 — `_SECRET_PATHS`, `_redact_path`, `redact_config`
- tests/test_redact_config.py — redaction behavior test suite
- tests/conftest.py — shared `config_base` fixture and `sys.path` setup
- tests/test_sync_provider_logging.py — representative `monkeypatch`-based test using the provider-scoped logger
- providers/auth/_auth_PLEX.py, providers/sync/_mod_SIMKL.py — representative provider module naming/structure
- api/syncAPI.py, api/editorAPI.py, api/authenticationAPI.py, api/configAPI.py — representative API route/error-handling patterns
- assets/js/main.js, assets/js/watchlist.js, assets/js/editor.js — representative non-module IIFE JS with camelCase naming
- android-companion/app/src/main/java/app/crosswatch/companion/MainActivity.java — actual app source is Java, not Kotlin, despite Kotlin-DSL Gradle build scripts

## Extended Sections (Optional)

Not populated — core sections are sufficient for current documentation needs.
