# External Integrations

## Core Sections (Required)

### 1) Integration Inventory

| System | Type (API/DB/Queue/etc) | Purpose | Auth model | Criticality | Evidence |
|--------|---------------------------|---------|------------|-------------|----------|
| Plex | REST API (media server) | Watchlist/ratings/history sync source-of-truth; scrobble webhook source | Device PIN flow — `POST /api/v2/pins` then poll for `authToken`, stored as `account_token` | High | providers/auth/_auth_PLEX.py:34,47,78,101,111-142 |
| Jellyfin | REST API (media server) | Watchlist/ratings/history sync; webhook/watcher scrobble source | Token flow — server URL + local username/password exchanged for API/access token | High | providers/auth/_auth_JELLYFIN.py:88,136,213 |
| Emby | REST API (media server) | Watchlist/ratings/history sync; webhook/watcher scrobble source | Token flow — server URL + local username/password exchanged for API key/access token | High | providers/auth/_auth_EMBY.py:87,131,207 |
| Trakt | REST API (tracker) | Watchlist/ratings/history sync; scrobble sink | OAuth2 device code (`/oauth/device/code` → `/oauth/device/token`); refresh via `/oauth/token` | High | providers/auth/_auth_TRAKT.py:49-52,133,250-309,311-361,363-436 |
| SIMKL | REST API (tracker) | Watchlist/ratings/history sync; scrobble sink | OAuth2 authorization-code flow; access tokens treated as long-lived, `refresh()` is a no-op | High | providers/auth/_auth_SIMKL.py:30-31,42,129-172,174-177 |
| AniList | GraphQL/REST API (tracker) | Anime watchlist/ratings/history sync | OAuth2 (`flow="oauth2"`) | Med | providers/auth/_auth_ANILIST.py:93 |
| MDBList | REST API (list/tracker) | List sync, ratings/watchlist enrichment; scrobble sink | Device code flow against `api.mdblist.com` | Med | providers/auth/_auth_MDBLIST.py:32,80,108,112 |
| Tautulli | REST API (monitoring, read-only) | History source only — feeds Plex playback history into sync; not bidirectional | API key | Low | providers/auth/_auth_TAUTULLI.py:30-45,77; providers/sync/_mod_TAUTULLI.py:1-2,50-60 ("history only", `"bidirectional": False`) |
| TMDb | REST API (metadata/enrichment) | Artwork, titles, ID enrichment for sync items | API key | Med | providers/auth/_auth_TMDB.py:39; providers/metadata/_meta_TMDB.py:29-60 |
| PublicMetaDB | REST API (metadata) | Supplemental metadata/ID mapping enrichment | API key | Low | providers/auth/_auth_PUBLICMETADB.py:21,92 |
| GitHub (anibridge-mappings releases) | Static file download (unauthenticated) | Pulls anime ID-mapping dataset for AniList↔TMDb/other ID cross-referencing | None (public GitHub release asset) | Low | cw_platform/anime_mapping/updater.py:29,45,62 |
| CrossWatch (internal tracker) | Internal, file-based, not an external system | Local snapshot/backup target for sync pairs | N/A (no HTTP; local state only) | Low | providers/sync/_mod_CROSSWATCH.py:1-30 |

### 2) Data Stores

| Store | Role | Access layer | Key risk | Evidence |
|-------|------|--------------|----------|----------|
| `config.json` | User configuration: provider credentials, sync pairs, feature toggles | cw_platform/config_base.py (`load_config`/`save_config`, atomic write) | Holds secrets; mitigated by field-level Fernet encryption at rest (see §3) | cw_platform/config_base.py:814,1604-1651,1654-1681 |
| `state.json` / `state.manual.json` | Current sync-run snapshots per provider, manually-pinned overrides merged in | cw_platform/orchestrator/_state_store.py:26-31,67-149 (atomic write via tmp-file `.replace()`) | Not encrypted; contains item-level watch state (low sensitivity) but is plaintext JSON | cw_platform/orchestrator/_state_store.py:57-64,137-149 |
| `tombstones.json` (in `.cw_state/`) | Deleted-item blacklist to prevent re-sync/resurrection | _state_store.py:34-35,152-177 (legacy-path auto-migration) | Plain JSON, no schema versioning beyond `ttl_sec` | cw_platform/orchestrator/_state_store.py:152-177 |
| `last_sync.json` | Most recent sync run result/summary | _state_store.py:38-39,179-180 | Plain JSON | cw_platform/orchestrator/_state_store.py:179-180 |
| `statistics.json` | Historical sync stats/metrics | services/statistics.py:18-24 | Plain JSON, unbounded growth possible (`[TODO]` on retention/rotation) | services/statistics.py:18-24 |
| Metadata cache (`cache/<movie\|show>/<tmdb_id>.<locale>.json`) | TTL'd cache of TMDb-enriched metadata (artwork/titles) | cw_platform/metadata_cache.py:17-51 | Path-traversal-safe via `relative_to()` checks; TTL-gated freshness | cw_platform/metadata_cache.py:24-51 |
| Config encryption key file | Fernet symmetric key protecting secret fields in `config.json` | cw_platform/config_base.py:44,84-109, perms `0o600` | Single key protects all secrets; loss makes existing secrets unrecoverable | cw_platform/config_base.py:90-109,136-151 |

All state/config stores are flat JSON files on disk under `CONFIG_BASE` — **there is no traditional database** (no SQL/NoSQL engine, no ORM found in the codebase).

### 3) Secrets and Credentials Handling

- **Credential sources**: exclusively `config.json`, populated via OAuth/PIN/token flows in `providers/auth/_auth_*.py` and written through `cw_platform.config_base.save_config`. No `.env` file loading or secrets-manager integration found.
- **Encryption at rest**: Confirmed. `cw_platform/config_base.py:194-204` (`_transform_secret_tree`) walks the config tree and, for any path matching `_is_sensitive_path()` (config_base.py:154-191 — covers `api_key`, `access_token`, `refresh_token`, `client_secret`, `password`, `webhook_secret`, `token_hash`, `salt`, `*_token`, etc.), encrypts values with Fernet before writing (config_base.py:123-133) and decrypts on load (config_base.py:136-151). Encrypted values are prefixed `enc:v1:` (config_base.py:42).
- **Key management**: Fernet key comes from env var `CW_CONFIG_KEY`/`CROSSWATCH_CONFIG_KEY` if set, else an auto-generated key file chmod'd `0600` (config_base.py:84-109). If the key is missing but encrypted data is present, `load_config` raises `RuntimeError` rather than silently failing open (config_base.py:142-145).
- **Redaction for display/logging**: Separate from encryption-at-rest — `redact_config()` (config_base.py:778-809) masks values for API/UI responses per `_SECRET_PATHS` (config_base.py:714-762). Verified by tests/test_redact_config.py.
- **In-process log redaction**: providers/auth/_auth_TRAKT.py:23-35 additionally regex-scrubs `access_token`/`refresh_token`/`client_secret`/`token`/`code` patterns out of free-text log messages before they reach the logger — a second, independent redaction layer specific to auth logging. `[TODO]` verify this scrub is applied consistently across all `_auth_*.py` modules, not just Trakt.
- **Hardcoding checks**: No hardcoded API keys/secrets found in the auth/sync modules sampled — credentials are read from the config object at call time. A full-repo secret-scan was not run — `[TODO]` if a stronger guarantee is needed.
- **Rotation or lifecycle notes**: `[ASK USER]` — no automatic credential-rotation logic found. Trakt implements proactive token refresh (`_auth_TRAKT.py:363-436`, refreshes when `expires_at` is within 120s); SIMKL explicitly treats its access token as long-lived and skips refresh. Plex/Emby/Jellyfin tokens have no observed expiry/rotation logic.

### 4) Reliability and Failure Behavior

- **Retry/backoff behavior**: Implemented centrally in providers/sync/_mod_common.py:521-639 (`request_with_retries`). Default `max_retries=3`, exponential backoff `backoff_base * (2**i)` (default base 0.5s), retries on status codes 429/500/502/503/504. For HTTP 429, honors `Retry-After` when present, taking `max(backoff, retry_after)`. Network exceptions are also retried with the same schedule; a final failure raises `requests.RequestException`.
- **Client-side rate limiting**: `SimpleRateLimiter` (_mod_common.py:38-70) enforces a minimum interval between GET/POST buckets per provider (configured via each provider's `rate_limit.{get_per_sec,post_per_sec}` in `config_base.py`), applied automatically inside `HitSession.request()`.
- **Timeout policy**: Configured per-provider in `DEFAULT_CFG` (cw_platform/config_base.py) — e.g. Plex `timeout: 10.0`/`max_retries: 3`, MDBList `timeout: 15.0`; others range 10-15s with `max_retries` 3-5. Auth-flow HTTP calls use their own inline timeouts (Plex PIN calls `HTTP_TIMEOUT=10`; Trakt device/token exchange 20-30s; SIMKL token exchange 12s).
- **Circuit-breaker or fallback behavior**: None found — no circuit breaker, bulkhead, or provider-fallback logic. Failure of a single sync source fails that pair's run rather than degrading to a cached/fallback source.

### 5) Observability for Integrations

- **Logging around external calls**: Yes. `_mod_common.py:83-118` (`_http_log`) emits structured log events (method, host/path-only URL via `_safe_url`, status, attempt, wait_s, dur_ms) for every retry, rate-limit backoff, and terminal failure, routed through `providers/sync/_log.py` into the app-wide `_logging.py` structured logger. Auth flows log at each step via each provider's local `log()` wrapper.
- **Metrics/tracing coverage**: None. No `opentelemetry`, `prometheus_client`, `statsd`, `sentry_sdk`, or `datadog` packages appear in requirements.txt/requirements-dev.txt, and no matching imports were found via repo-wide grep.
- **Missing visibility gaps**:
  - No metrics export (request counts, latency histograms, error rates) beyond ad hoc log lines.
  - No distributed tracing / correlation IDs across a sync run spanning multiple provider calls.
  - `statistics.json` captures sync-run business outcomes, not infra/API-health telemetry.
  - Rate-limit throttling is logged only in aggregate/throttled summaries (min 60s window or 0.5s sleep threshold) — sub-threshold throttling is invisible.

### 6) Evidence

- providers/auth/_auth_PLEX.py, _auth_TRAKT.py, _auth_SIMKL.py, _auth_ANILIST.py, _auth_MDBLIST.py, _auth_EMBY.py, _auth_JELLYFIN.py, _auth_TMDB.py, _auth_PUBLICMETADB.py, _auth_TAUTULLI.py — per-provider auth flows
- providers/sync/_mod_common.py — shared HTTP session, retry/backoff, rate limiting, structured HTTP logging
- providers/webhooks/_utils.py, plextrakt.py:1010-1130, embytrakt.py:851-854, jellyfintrakt.py:1036-1039, tests/test_webhook_secret.py — inbound webhook shared-secret verification. **Important gap**: Plex uses HMAC-SHA1 `X-Plex-Signature`; Emby/Jellyfin use plain `X-CW-Webhook-Secret` compared with `hmac.compare_digest` — but **all three fail open**, skipping auth with only a WARN log when `webhook_secret` is unset (plextrakt.py:1016-1022). See CONCERNS.md.
- cw_platform/url_validation.py, tests/test_url_validation.py, api/configAPI.py:425-446 — `validate_server_url` is **advisory only**: returns warning strings, never raises/blocks, does not reject private/RFC-1918 IPs by design, only flags bad scheme, missing hostname, two hardcoded cloud-metadata hosts, and `..` path traversal. The README's "SSRF guarded" claim should be read as "best-effort warning-only checks on media-server URLs at save time," not a runtime request-blocking guard. See CONCERNS.md.
- cw_platform/config_base.py:42-204,700-819,1604-1690 — secret encryption (Fernet), key management, redaction, config.json load/save
- cw_platform/orchestrator/_state_store.py — state.json, state.manual.json, tombstones.json, last_sync.json flat-file, atomic-write store
- services/statistics.py:18-24 — statistics.json store
- cw_platform/metadata.py, cw_platform/metadata_cache.py, providers/metadata/_meta_TMDB.py, providers/metadata/registry.py — metadata enrichment (TMDb) and its on-disk TTL cache
- cw_platform/anime_mapping/updater.py:29,45,62 — unauthenticated GitHub release-asset fetch for anime ID mapping data
- providers/scrobble/scrobble.py:349-502 (`Dispatcher.dispatch()`) — confirms scrobble routing is in-process/synchronous, not a message queue; no queue/broker library found anywhere in the repo
- requirements.txt — full runtime dependency list; confirms absence of any metrics/tracing/APM library
- tests/test_redact_config.py, tests/test_url_validation.py, tests/test_webhook_secret.py — test coverage backing the above claims

## Extended Sections (Optional)

Not populated — core sections are sufficient for current documentation needs.
