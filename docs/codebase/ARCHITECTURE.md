# Architecture

## Core Sections (Required)

### 1) Architectural Style

- **Primary style:** Layered + feature-sliced FastAPI application, with an embedded event-driven subsystem for real-time scrobbling.
- **Why this classification:** `crosswatch.py` builds a single `FastAPI()` app (crosswatch.py:393) and registers ~20 feature-scoped routers through `api/__init__.py::register()` (api/__init__.py:78-113, e.g. `syncAPI`, `editorAPI`, `scrobbleAPI`, `schedulingAPI`, `insightAPI`). All routers funnel domain work into a single `Orchestrator` facade (cw_platform/orchestrator/facade.py:48-499) that coordinates dynamically-loaded provider adapters (`providers/sync/_mod_*.py`) implementing a shared `InventoryOps` protocol (cw_platform/orchestrator/_types.py:11-38). Real-time scrobbling is separately event-driven: webhooks/watchers emit `ScrobbleEvent`s consumed by a `Dispatcher` that fans out to `ScrobbleSink` implementations (providers/scrobble/scrobble.py:349-515).
- **Primary constraints:**
  - Single-user, single-process deployment (per CLAUDE.md); config changes require a full restart — `CONFIG_BASE()`/`CONFIG` are resolved and created **at import time** (cw_platform/config_base.py:28-40).
  - All persistent state is flat JSON files under `CONFIG_BASE` (`state.json`, `tombstones.json`, `last_sync.json`), read/written via `StateStore` (cw_platform/orchestrator/_state_store.py:12-197) — no database.
  - Only one sync run may execute at a time, enforced by a module-level `threading.Lock` (crosswatch.py:110, gated in api/syncAPI.py:2050-2089), because pair-scoping is threaded through process-global `os.environ` mutations rather than explicit call arguments (cw_platform/orchestrator/_pairs.py:198-229).

### 2) System Flow

```text
[crosswatch.py: FastAPI app + lifespan] -> [api/*API.py routers, e.g. syncAPI.api_run_sync]
   -> [Orchestrator.run() facade.py:154] -> [_pairs.run_pairs() _pairs.py:231]
      -> per pair/feature: [_snapshots.build_snapshots_for_feature() _snapshots.py:574]
         calls provider OPS.build_index() (e.g. _PlexOPS.build_index _mod_PLEX.py:1314-1315)
      -> [_pairs_oneway.run_one_way_feature() / _pairs_twoway.run_two_way_feature()]
         -> [_planner.diff()/diff_ratings()/diff_progress() _planner.py:72-383]
      -> [_applier.apply_add()/apply_remove() _applier.py:298-452] calls OPS.add()/remove()
   -> [_state_store.StateStore.save_state()/save_last() _state_store.py:145-180]
      + [_tombstones.cascade_removals() _tombstones.py:211-220]
   -> [Stats.record_summary / STATS singleton crosswatch.py:103] -> UI log buffers/SSE (crosswatch.py:631-1010)
```

Config is loaded per-call via `load_config()` (cw_platform/config_base.py), not cached across requests; the `Orchestrator` is instantiated fresh per run (crosswatch.py:712-714, docker/run-sync.py:24).

### 3) Layer/Module Responsibilities

| Layer or module | Owns | Must not own | Evidence |
|-----------------|------|--------------|----------|
| `crosswatch.py` (entrypoint) | FastAPI app/middleware wiring, lifespan startup (scheduler/watcher autostart), SSE log streaming, TLS bootstrap | Sync business logic, provider I/O | crosswatch.py:393-819 |
| `api/*API.py` (HTTP layer) | Route handlers, request validation, thread spawning for long-running sync | Provider protocol details, diff/apply logic | api/__init__.py:78-113, api/syncAPI.py:2046-2089 |
| `cw_platform/orchestrator/facade.py` (`Orchestrator`) | Run lifecycle, config→context assembly, state persistence orchestration | HTTP concerns, provider-specific API calls | cw_platform/orchestrator/facade.py:48-225 |
| `cw_platform/orchestrator/_pairs*.py` | Per-pair/per-feature sync algorithm (one-way/two-way), health gating, pair-scoped env context | Provider HTTP/auth details | cw_platform/orchestrator/_pairs.py:231-527 |
| `cw_platform/orchestrator/_snapshots.py` / `_planner.py` / `_applier.py` | Snapshot fetch/cache, diff computation, chunked add/remove application | State-file I/O, provider discovery | _snapshots.py:574-673, _planner.py:72-102, _applier.py:298-452 |
| `cw_platform/orchestrator/_state_store.py` / `_tombstones.py` | JSON state persistence, tombstone lifecycle | Diff/apply business rules | _state_store.py:137-197, _tombstones.py:18-220 |
| `cw_platform/modules_registry.py` / `_providers.py` | Provider module lookup/loading (two separate mechanisms — see Known Architectural Risks) | Sync algorithm logic | modules_registry.py:11-50, _providers.py:15-47 |
| `providers/sync/_mod_*.py` | `InventoryOps` implementation per provider (`name/label/features/build_index/add/remove`) | Cross-provider diffing, state persistence | providers/sync/_mod_PLEX.py:1267-1338 |
| `providers/scrobble/*` | Webhook/watcher event parsing, dispatcher→sink fan-out for real-time scrobbles | Full sync-pair reconciliation | providers/scrobble/scrobble.py:193-515 |
| `services/scheduling.py` (`SyncScheduler`) | Cron-like scheduling, event-triggered sync dispatch | Sync execution itself (delegates via `run_sync_fn`) | crosswatch.py:1197-1202, services/scheduling.py:1-39 |
| `services/snapshots.py`, `services/backups.py`, etc. | Feature-specific higher-level workflows (capture/backup) | — | services/snapshots.py:155-183 (calls provider ops directly, bypassing Orchestrator — see risks) |

### 4) Reused Patterns

| Pattern | Where found | Why it exists |
|---------|-------------|---------------|
| Protocol/Adapter | `InventoryOps` protocol (cw_platform/orchestrator/_types.py:11-38) implemented by thin `OPS` adapter classes, e.g. `_PlexOPS` (providers/sync/_mod_PLEX.py:1267-1338) wrapping `PLEXModule` | Uniform snapshot/add/remove surface so the orchestrator is provider-agnostic |
| Registry (dynamic discovery) | `load_sync_providers()` scans `providers/sync/_mod_*.py` via `pkgutil` and duck-types for `OPS`/`ADAPTER` (cw_platform/orchestrator/_providers.py:15-47) | Auto-registers new provider modules without a central list |
| Registry (static table) | `MODULES["SYNC"]` hardcoded dict + `load_sync_ops()` (cw_platform/modules_registry.py:11-50) | Used by non-Orchestrator callers (e.g. snapshot capture) that need a single provider's ops without loading all of them |
| Dispatcher/Observer | `Dispatcher` class fans `ScrobbleEvent` out to `ScrobbleSink` implementers (providers/scrobble/scrobble.py:349-515) | Decouples webhook/watcher event sources from Trakt/SIMKL/MDBList sinks |
| Module-level singleton | `STATS = Stats()` (crosswatch.py:103), `scheduler = SyncScheduler(...)` (crosswatch.py:1197), `_METADATA = _MetadataMgr(...)` (crosswatch.py:1207), `CONFIG` resolved+created at import (cw_platform/config_base.py:28-40) | Simple single-process app; avoids a DI container |
| Ambient context via `os.environ` | `_pair_env`/`_health_env` context managers mutate `CW_PAIR_KEY`, `CW_PAIR_SCOPE`, etc. for the duration of a provider call (cw_platform/orchestrator/_pairs.py:74-100, 198-229) | Lets deeply-nested provider code (loggers, caches) recover "which pair/feature is running" without threading a parameter through every call |
| Runtime attribute injection on modules | `inject_ctx_into_provider()` calls `setattr(mod, "ctx", ctx)` on the imported provider module itself (cw_platform/orchestrator/_pairs_utils.py:69-104) | Gives provider code (e.g. `_mod_PLEX.py:72-75`'s top-level `ctx` global) access to orchestrator context without changing every function signature |

### 5) Known Architectural Risks

- **Shadowed/dead compat file — `cw_platform/orchestrator.py`.** A 5-line module that tries to re-export `Orchestrator` etc. "from .orchestrator", but a same-named package `cw_platform/orchestrator/` sits next to it. Python's import resolution always finds the package first — this file is unreachable dead code that could mislead a future maintainer into editing the wrong "orchestrator.py". Low runtime impact, real maintenance-trap risk.
- **Broken `docker/run-sync.py`.** It calls `Orchestrator()` with no arguments (docker/run-sync.py:24), but `Orchestrator` is a dataclass whose first field `config: Mapping[str, Any]` has no default (cw_platform/orchestrator/facade.py:50) — this raises `TypeError` at runtime. This script is the documented way to trigger a sync via `docker exec` and is currently non-functional.
- **Two independent, drift-prone provider-loading mechanisms.** `cw_platform/modules_registry.py:24-36` hardcodes a `MODULES["SYNC"]` dict used by `load_sync_ops()`, while `cw_platform/orchestrator/_providers.py:15-47` dynamically discovers the same modules via `pkgutil` for the Orchestrator's own provider map. Both are live simultaneously (`services/snapshots.py:18,155` uses the former directly; `facade.py:88` uses the latter). Adding a provider requires remembering to update the static dict even though the dynamic path would find it automatically, and the two lists can silently diverge.
- **Global mutable process state for run-scoping, used outside the Orchestrator's own lock.** `_pair_env`/`_health_env` mutate `os.environ` for the life of a provider call, and `inject_ctx_into_provider()` sets a `ctx` attribute directly on the cached provider *module* object — both are process-wide, not thread-local. `services/snapshots.py:155,183,753,975` calls `ops.build_index()` directly via `modules_registry.load_sync_ops()`, entirely outside `_pairs.py` and `SYNC_PROC_LOCK` (crosswatch.py:110, which only guards `/api/sync/run`). A snapshot/capture request running concurrently with an in-progress sync can race on the same module-level `ctx`/env-var state with no lock coordinating the two paths.
- **God-files.** Several files mix many concerns and exceed 1,500–3,200 lines: `services/analyzer.py` (3195 lines), `api/syncAPI.py` (2248 lines), `cw_platform/orchestrator/_pairs_twoway.py` (2060 lines), `api/insightAPI.py` (1914 lines), `cw_platform/orchestrator/_pairs_oneway.py` (1602 lines), and the entrypoint `crosswatch.py` itself (1282 lines, mixing FastAPI bootstrap, ANSI-to-HTML log rendering, SSE streaming, TLS cert generation, and scheduler wiring). This raises the blast radius of any change and makes isolated unit testing harder.
- **Pervasive silent exception swallowing.** Nearly every `try/except Exception: pass` in the orchestrator hot path degrades silently around stats emission, state persistence, and tombstone pruning (e.g. cw_platform/orchestrator/facade.py:192-220, cw_platform/orchestrator/_pairs.py:427-495). Favors availability, but a failing state/stat write is masked rather than surfaced.
- **Accumulated compat-shim debt.** The Orchestrator logs `"Orchestrator v3 ready (full compat shims)"` on init (cw_platform/orchestrator/facade.py:123), and `Orchestrator.run_pairs()`/`run_pair()` are thin aliases over `run()` (facade.py:227-253) — evidence of at least one prior rewrite whose compatibility surface is still carried forward.

### 6) Evidence

- crosswatch.py:1-1283 (entrypoint, FastAPI app, lifespan, middleware, scheduler/metadata singletons)
- api/__init__.py:1-113 (router registration)
- api/syncAPI.py:2045-2089 (sync trigger endpoint, lock/thread handling)
- cw_platform/orchestrator.py:1-5 (dead compat shim)
- cw_platform/orchestrator/__init__.py:1-7 (actual package public surface)
- cw_platform/orchestrator/facade.py:1-499 (`Orchestrator` class)
- cw_platform/orchestrator/_pairs.py:1-528 (`run_pairs`, pair/health env scoping)
- cw_platform/orchestrator/_pairs_utils.py:1-212 (`inject_ctx_into_provider`, module-global `ctx` injection)
- cw_platform/orchestrator/_snapshots.py:1-732, _planner.py:1-384, _applier.py:1-453, _state_store.py:1-197, _tombstones.py:1-221
- cw_platform/orchestrator/_providers.py:1-48, cw_platform/modules_registry.py:1-70, cw_platform/manager.py:1-156
- cw_platform/config_base.py:1-60 (import-time `CONFIG_BASE` resolution)
- providers/sync/_mod_common.py:1-643 (shared HTTP session/retry/rate-limit helpers)
- providers/sync/_mod_PLEX.py:1-1341 (concrete `InventoryOps` adapter, `_PlexOPS` at 1267-1338)
- providers/scrobble/scrobble.py:1-526 (`Dispatcher`/`ScrobbleSink` event-driven subsystem)
- services/scheduling.py:1-130 (`SyncScheduler`, `DEFAULT_SCHEDULING`)
- services/snapshots.py:18,155,183,753,975 (direct, Orchestrator-bypassing provider calls)
- docker/run-sync.py:1-36 (broken standalone sync entrypoint)

## Extended Sections (Optional)

Not populated — core sections are sufficient for current documentation needs.
