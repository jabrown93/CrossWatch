# Testing Patterns

## Core Sections (Required)

### 1) Test Stack and Commands

- Primary test framework: **pytest** `>=8.0` (requirements-dev.txt:1)
- Assertion/mocking tools: pytest's built-in `assert` rewriting; `pytest.MonkeyPatch` fixture (used in 19-22 of ~30 test files, e.g. tests/test_orchestrator_oneway_watchlist.py:82, providers/tests/test_health_smoke.py:23); the `responses` library (requirements-dev.txt:3, used only in tests/test_version_api.py:7,23 via `responses.RequestsMock()` — repo-wide grep for `@responses.activate` found zero hits elsewhere); `fastapi.testclient.TestClient` (requirements-dev.txt:5, used only in tests/test_version_api.py:5); hand-rolled fake/stub classes standing in for provider sessions/ops (e.g. `FakeOps` in tests/test_orchestrator_oneway_watchlist.py:13-78, `ResponseStub` in providers/tests/test_health_smoke.py:9-19). Repo-wide grep found **zero** uses of `unittest.mock`.
- Commands:

```bash
# run all tests (as CI does, minus the deselects — see §5)
python -m pytest

python -m pytest tests/           # tests/ suite only
python -m pytest providers/tests/ # providers/ suite only (see structural note below)

# coverage: pytest-cov is a declared dev dependency but is NOT invoked in CI
# or any checked-in config — this is a manual/ad-hoc command, not a repo convention:
python -m pytest --cov
```

### 2) Test Layout

- Test file placement pattern: **centralized `tests/` folders, not co-located with source.** Every `test_*.py` file lives under either `tests/` or `providers/tests/`; none sit beside the modules they test.
- Naming convention: `test_*.py` files (enforced by `python_files = test_*.py` in pytest.ini:3); mostly free functions named `test_<behavior>`, with one class-based exception (`TestSharedVerifyWebhookSecret`, etc. in tests/test_webhook_secret.py:9,26,43). `@pytest.mark.parametrize` is used for table-driven contract tests (providers/tests/test_manifests.py, test_confirmed_keys.py:19, test_health_smoke.py) — no other custom pytest markers are defined or used.
- Setup files and where they run:
  - tests/conftest.py:9-11 — inserts repo root onto `sys.path`; defines one fixture, `config_base` (tests/conftest.py:14-17), pointing `CONFIG_BASE` at a `tmp_path` via `monkeypatch.setenv`.
  - providers/tests/conftest.py:214-221 — a session-scoped **autouse** fixture `_bootstrap_test_env` that (a) puts both repo root and `providers/` on `sys.path`, (b) installs stub modules for `cw_platform.id_map`/`provider_instances`/`config_base`/`idutils` only if the real `cw_platform` package can't be imported — i.e. `providers/` is built to be testable as a **standalone extracted package**, not just inside the monorepo, and (c) stubs `providers.auth._auth_TRAKT` with a fake in-memory token store.

**Structural oddity:** there are two separate `pytest.ini` files — the root one (`addopts = -q --disable-warnings --maxfail=1`, `python_files = test_*.py`, no `testpaths`) and `providers/pytest.ini` (`testpaths = tests`, `addopts = -q`). CI (.github/workflows/ci.yml:44-48) invokes `python -m pytest` from the repo root with no positional path or `-c` override. Per pytest's single-ini-file discovery, only the root file governs that run; since it sets no `testpaths`/`norecursedirs`, it still recurses into and collects `providers/tests/*.py`, but under the root file's `addopts`, not `providers/pytest.ini`'s. No Makefile/script/workflow step `cd`s into `providers/` to invoke pytest there, so `providers/pytest.ini` appears to be dead configuration for the actual CI pipeline today — it only takes effect if someone runs pytest with `providers/` as the working directory, which the conftest.py stubbing above suggests was the original intent. **Caveat:** inferred from pytest's rootdir/ini-selection semantics, not from an executed pytest run in this environment.

### 3) Test Scope Matrix

| Scope | Covered? | Typical target | Notes |
|-------|----------|----------------|-------|
| Unit | Yes | Pure functions/helpers: `cw_platform/orchestrator/_planner.py` diff logic (tests/test_planner.py, no mocking at all), `cw_platform/config_base.py` secret redaction (tests/test_redact_config.py), webhook secret comparison (tests/test_webhook_secret.py), provider history/ID helpers (tests/test_history_specials.py) | Majority of the suite; heavy use of `monkeypatch` to isolate a function from its module-level collaborators rather than real unit isolation via DI |
| Integration | Yes | Orchestrator sync runs against fake in-memory provider ops (tests/test_orchestrator_oneway_watchlist.py, `Orchestrator(cfg).run()` at lines 138-152); FastAPI route wiring via `TestClient` (tests/test_version_api.py) | Only `test_version_api.py` exercises a real ASGI request/response cycle; API-handler tests like tests/test_config_api.py:4-40 and tests/test_app_auth_api.py call route functions directly with monkeypatched dependencies rather than going through HTTP |
| E2E | No | — | No browser/UI-driven or full-stack (real Plex/Trakt/etc.) end-to-end tests found; all "integration" tests substitute fakes/stubs for real provider HTTP |

### 4) Mocking and Isolation Strategy

- Main mocking approach: `pytest.monkeypatch` to replace module-level functions/attributes, plus hand-rolled fake classes implementing just enough of a provider/session interface. The `responses` HTTP-mocking library is a declared dependency but used in exactly one file; `unittest.mock` is not used anywhere.
- Isolation guarantees: tests/conftest.py:14-17's `config_base` fixture redirects `CONFIG_BASE` to a fresh `tmp_path` per test via `monkeypatch` (auto-reverted at teardown). providers/tests/conftest.py:214-221's autouse session fixture sets `CW_LOG_LEVEL=off` and installs `sys.modules` stubs once per session (not per-test) — coarser, session-wide isolation. No database/filesystem reset fixtures beyond `tmp_path`/`monkeypatch`; no global "disable network" fixture observed.
- Common failure mode in tests: `pytest.ini`'s `--maxfail=1` means a single failing test aborts the entire run immediately, masking failures elsewhere until the first is fixed — this is also why CI needs four explicit `--deselect` flags rather than letting known-broken tests fail and continue.

### 5) Coverage and Quality Signals

- Coverage tool + threshold: `pytest-cov>=5.0` is a declared dev dependency but **never invoked** — the CI test step runs plain `python -m pytest` with no `--cov` flag, and no `.coveragerc`/`[tool.coverage]` config exists. No threshold enforced. `[TODO]`
- Current reported coverage: `[TODO]` — not measured/reported anywhere in CI or committed config.
- Known gaps/flaky areas: Four tests are permanently deselected in CI (.github/workflows/ci.yml:44-48):
  - `tests/test_dashboard_widgets.py::test_recent_scrobble_widget_uses_nested_history_sync_item_art`
  - `tests/test_meta_api_episode_stills.py::test_episode_still_art_is_fetched_and_cached`
  - `tests/test_playback_progress.py::test_same_title_with_matching_progress_can_still_combine_across_profiles`
  - `tests/test_app_auth_api.py::test_setup_lock_not_required_when_up_to_date_without_auth`

  Per the inline CI comment and README.md:22-23, these are pre-existing upstream (cenodude/CrossWatch) bugs that fail even on a pristine upstream checkout, deselected to keep this fork's CI green — tracked for removal once upstream fixes land. Other gaps: no JS/frontend test runner exists (package.json declares only eslint/prettier devDependencies, no `"scripts"` block, no `*.test.js`/`*.spec.js` files anywhere). No Android tests either — `android-companion/app/src` contains only `main/` (no `test/` or `androidTest/` directories).

### 6) Evidence

- pytest.ini, providers/pytest.ini
- tests/conftest.py, providers/tests/conftest.py
- tests/test_orchestrator_oneway_watchlist.py, tests/test_planner.py, tests/test_history_specials.py, tests/test_redact_config.py, tests/test_webhook_secret.py, tests/test_version_api.py, tests/test_config_api.py, tests/test_app_auth_api.py
- providers/tests/test_health_smoke.py, test_manifests.py, test_confirmed_keys.py
- requirements-dev.txt
- .github/workflows/ci.yml
- README.md:22-23
- package.json
- android-companion/app/src (absence of test/androidTest/)

## Extended Sections (Optional)

Not populated — core sections are sufficient for current documentation needs.
