# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CrossWatch (CW) is a synchronization engine that keeps Plex, Jellyfin, Emby, SIMKL, Trakt, AniList, MDBList, and Tautulli in sync. It's a FastAPI-based web application with a built-in UI that runs locally or in Docker.

**Key capabilities:**
- Sync watchlists, ratings, and history between media servers and trackers (one-way or two-way)
- Live scrobbling (real-time watch tracking) via webhooks and watchers
- Internal CrossWatch tracker for snapshots/backups
- Analyzer for detecting stuck or inconsistent items
- Editor for inspecting and adjusting sync items
- Scheduling for automated sync runs

**Supported providers:**
- Media servers: Plex, Jellyfin, Emby
- Trackers: SIMKL, Trakt, AniList, MDBList, CrossWatch (internal)
- Monitoring: Tautulli

**Not supported:** Multi-user or multi-server configurations

## Development Commands

### Running the Application

```bash
# Run locally (starts web UI on port 8787)
python crosswatch.py

# Run with specific host/port
python -c "from crosswatch import main; main(host='0.0.0.0', port=8787)"
```

### Docker

```bash
# Build image
docker build -t crosswatch .

# Run container
docker run -d --name crosswatch -p 8787:8787 -v /path/to/config:/config -e TZ=Europe/Amsterdam crosswatch

# Or use docker-compose
docker-compose up -d
```

### Testing

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run all tests
pytest

# Run specific test file
pytest tests/test_version_api.py

# Run with coverage
pytest --cov

# Tests configuration is in pytest.ini
# Default options: -q --disable-warnings --maxfail=1
```

### Linting

```bash
# The project has ESLint and Prettier configured for any JavaScript/frontend assets
# (primarily for the UI frontend in assets/)

# Install Node dependencies
npm install

# Note: No explicit npm scripts are defined, but eslint/prettier are available
npx eslint .
npx prettier --check .
```

## Architecture

### Entry Point and Core Flow

**crosswatch.py** is the main entry point. It:
1. Initializes FastAPI app with lifespan context manager
2. Registers all API routers and services
3. Mounts static assets from `assets/`
4. Starts scrobble dispatchers (webhooks/watchers) if configured
5. Launches uvicorn server on port 8787

The application uses a config-driven architecture where `config.json` (stored in `CONFIG_BASE` directory) controls all provider credentials, sync pairs, and runtime settings.

### Key Directories

- **`api/`** - FastAPI route handlers organized by feature
  - `authenticationAPI.py` - Provider OAuth flows and authentication
  - `syncAPI.py` - Sync execution endpoints
  - `scrobbleAPI.py` - Real-time scrobble control (webhooks/watchers)
  - `watchlistAPI.py` - Unified watchlist view
  - `editorAPI.py` - Item inspection and editing
  - `insightAPI.py` - Analytics and statistics
  - `probesAPI.py` - Provider connectivity checks
  - `metaAPI.py` - Metadata lookup and enrichment
  - `maintenanceAPI.py` - System maintenance tasks
  - `configAPI.py` - Configuration management
  - `schedulingAPI.py` - Scheduler control
  - `versionAPI.py` - Version information and update checks
  - `wallAPI.py` - "Now Playing" card data

- **`cw_platform/`** - Core sync engine (orchestrator)
  - `orchestrator/` - The heart of CrossWatch sync logic
    - `facade.py` - Main `Orchestrator` class that coordinates sync runs
    - `_pairs_oneway.py` - One-way sync logic (A → B)
    - `_pairs_twoway.py` - Two-way sync logic (A ↔ B)
    - `_snapshots.py` - Snapshot management for tracking provider state
    - `_planner.py` - Diff calculation between snapshots
    - `_applier.py` - Applies add/remove operations to providers
    - `_state_store.py` - Manages state.json persistence
    - `_tombstones.py` - Tracks deleted items to prevent re-sync
    - `_telemetry.py` - Stats and rate limit tracking
    - `_blackbox.py` - Filters for automated decisions
    - `_phantoms.py` - Handles items that exist in one provider but not another
    - `_unresolved.py` - Manages items with missing metadata/IDs
  - `config_base.py` - Configuration loading and defaults (extensive provider settings)
  - `id_map.py` - ID mapping utilities for cross-provider matching
  - `metadata.py` - Metadata resolution and enrichment
  - `manager.py` - Provider instantiation
  - `modules_registry.py` - Dynamic provider module loading

- **`providers/`** - Provider implementations
  - `auth/` - Authentication modules per provider (`_auth_PLEX.py`, `_auth_SIMKL.py`, etc.)
  - `sync/` - Sync modules per provider
    - Each provider has a directory (e.g., `plex/`, `simkl/`, `trakt/`) with:
      - Watchlist handlers
      - History handlers
      - Ratings handlers
    - `_mod_*.py` files define the sync interface for each provider
    - `_mod_common.py` - Shared utilities (HTTP sessions, retry logic, rate limit parsing)
  - `scrobble/` - Real-time scrobbling implementations
    - `scrobble.py` - Main dispatcher that routes events to sinks
    - `plex/watch.py` - Plex watcher service (plugin-free)
    - `emby/watch.py` - Emby watcher service
    - `jellyfin/watch.py` - Jellyfin watcher service
    - `trakt/sink.py` - Trakt scrobble sink
    - `simkl/sink.py` - SIMKL scrobble sink
    - `mdblist/sink.py` - MDBList scrobble sink
    - `currently_watching.py` - Tracks active playback sessions
    - `_auto_remove_watchlist.py` - Removes from watchlist after completion
  - `webhooks/` - Webhook receivers (Plex, Emby, Jellyfin)
  - `metadata/` - Metadata enrichment providers

- **`services/`** - Higher-level services
  - `analyzer.py` - Detects inconsistencies and stuck items
  - `editor.py` - Item CRUD operations
  - `export.py` - CSV export for external services
  - `scheduling.py` - Cron-style scheduler for automated syncs
  - `statistics.py` - Stats aggregation and persistence
  - `watchlist.py` - Unified watchlist aggregation

- **`scripts/`** - Standalone maintenance scripts
  - `*_cleanup.py` - Provider-specific cleanup utilities (plex, simkl, trakt, emby, jellyfin, mdblist)

- **`ui_frontend.py`** - UI registration (serves single-page app and favicon)

- **`_logging.py`** - Structured logging with color support

### Sync Engine Flow

When a sync runs (via UI or `/docker/run-sync.sh`):

1. **Load config** from `config.json` (via `cw_platform/config_base.py`)
2. **Instantiate Orchestrator** (`cw_platform/orchestrator/facade.py`)
3. **Load providers** for configured sync pairs (`cw_platform/manager.py`)
4. **Build snapshots** - Fetch current state from each provider (`_snapshots.py`)
5. **Calculate diffs** - Compare snapshots to detect changes (`_planner.py`)
6. **Apply changes** - Add/remove items based on sync pair direction (`_applier.py`)
7. **Update tombstones** - Record deletions to prevent re-sync (`_tombstones.py`)
8. **Write state.json** - Persist final state for next run (`_state_store.py`)
9. **Update statistics** - Record metrics in `statistics.json` (`services/statistics.py`)

### Provider Interface

All sync providers must implement the `InventoryOps` protocol (defined in `cw_platform/orchestrator/_types.py`):

- `snapshot(feature, prev_snapshot, progress_fn)` - Fetch current state for a feature (watchlist/history/ratings)
- `add(feature, items)` - Add items to the provider
- `remove(feature, items)` - Remove items from the provider

Each provider module (`providers/sync/_mod_*.py`) exports these functions and is loaded dynamically by `cw_platform/modules_registry.py`.

### Configuration Management

The config is stored in `CONFIG_BASE/config.json` where `CONFIG_BASE` is:
- `/config` inside Docker containers (mounted volume)
- Environment variable `CONFIG_BASE` if set
- Repository root otherwise

Important config keys are documented extensively in `cw_platform/config_base.py:38-200` (DEFAULT_CFG dict). Each provider section contains credentials, API settings, timeouts, retry logic, library filters, and feature-specific toggles.

### State Files

All runtime state is stored in `CONFIG_BASE`:
- `config.json` - User configuration
- `state.json` - Current sync state (snapshots, tombstones)
- `statistics.json` - Historical sync stats
- `last_sync.json` - Most recent sync result
- `tombstones.json` - Deleted items blacklist
- `cache/` - Temporary metadata cache
- `reports/` - Export outputs

## Common Patterns

### Adding a New Provider

1. Create auth module in `providers/auth/_auth_NEWPROVIDER.py`
2. Create sync module in `providers/sync/_mod_NEWPROVIDER.py` implementing `snapshot`, `add`, `remove`
3. Create provider directory `providers/sync/newprovider/` with feature handlers
4. Add default config section in `cw_platform/config_base.py`
5. Register in `cw_platform/modules_registry.py` if not using auto-discovery
6. Add API endpoints in `api/authenticationAPI.py` for OAuth flow
7. Update UI assets to include provider branding

### Testing Provider Code

Tests use `pytest` with fixtures defined in `tests/conftest.py`. Provider sync modules should be tested with mocked HTTP responses using the `responses` library.

Example test structure:
```python
import responses
from providers.sync._mod_PROVIDER import snapshot, add, remove

@responses.activate
def test_snapshot_watchlist():
    responses.add(responses.GET, "https://api.provider.com/watchlist", json={"items": []})
    result = snapshot("watchlist", {}, lambda x: None)
    assert result == {}
```

### Working with the Orchestrator

The `Orchestrator` class (`cw_platform/orchestrator/facade.py`) is the main interface for sync operations. It handles:
- Provider loading and configuration
- Snapshot caching with TTL
- Conflict resolution policies
- Dry-run mode
- Progress callbacks
- State persistence

To run a sync programmatically:
```python
from cw_platform.orchestrator import Orchestrator
from cw_platform.config_base import load_config

config = load_config()
orc = Orchestrator(config=config)
result = orc.run_pairs(dry_run=False, write_state_json=True)
print(f"Added: {result['added']}, Removed: {result['removed']}")
```

### Scrobbling Architecture

Scrobbling (real-time watch tracking) uses a dispatcher-sink pattern:

1. **Sources** (webhooks or watchers) emit playback events
2. **Dispatcher** (`providers/scrobble/scrobble.py`) receives events
3. **Sinks** (`trakt/sink.py`, `simkl/sink.py`, etc.) receive events and call provider APIs

Watchers poll media servers for active sessions (Plex, Emby, Jellyfin).
Webhooks receive HTTP callbacks from media servers (Plex, Emby, Jellyfin).

The dispatcher tracks currently watching state in `currently_watching.py` and optionally auto-removes items from watchlists after completion via `_auto_remove_watchlist.py`.

## Important Notes

- **No external contributions accepted** currently (see CONTRIBUTING.md)
- **Security vulnerabilities** should be reported privately (see SECURITY.md)
- The codebase uses **type hints** extensively (`from __future__ import annotations`)
- All provider modules use structured logging via `_logging.py`
- HTTP sessions are managed by `providers/sync/_mod_common.py` with retry logic and rate limit handling
- The application is designed to run as a single-user, single-server instance
- Config changes require restart (no hot reload)