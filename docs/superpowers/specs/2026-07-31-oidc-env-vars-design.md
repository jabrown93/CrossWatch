# Environment-variable configuration for OIDC (and any config path)

Date: 2026-07-31
Status: Approved

## Problem

`app_auth.oidc.*` and `security.api_key` can only be set by editing `config.json`. In a
container deployment the natural source for those values — especially `client_secret` and
`api_key` — is the environment (Docker `environment:`, a Kubernetes Secret, a GitOps-managed
manifest). Today an operator has to bake secrets into a mounted `config.json` and keep it out
of version control by hand.

Two further problems fall out of adding env support:

1. `save_config` writes the whole config back to disk. An env-injected secret would be
   persisted into `config.json` on the next save, defeating the point.
2. The UI edits config fields freely. If an env var owns a field, a UI edit appears to save
   and then silently reverts on the next load.

## Goals

- Set any `app_auth.oidc.*` field and `security.api_key` from the environment.
- Set any other config path from the environment via a generic escape hatch.
- Env-injected values never land in `config.json`.
- The UI shows env-owned fields as locked, and a save that discards an env-owned change says so.
- OIDC becomes configurable from the UI at all (it has no settings pane today).

## Non-goals

- Reloading config when the environment changes at runtime. Env is read per `load_config()`
  call; a container restart is the update mechanism, consistent with "config changes require
  restart" in CLAUDE.md.
- Addressing list elements (`pairs[0]`, scrobbler routes) from the environment. See Limitations.
- Any change to how secrets are encrypted at rest.

## Design

### 1. `cw_platform/config_env.py` (new)

A standalone module with no `config_base` import, so there is no import cycle — `config_base`
imports it, not the reverse.

```python
def env_overrides(environ: Mapping[str, str] | None = None) -> dict[tuple[str, ...], Any]
def apply_env_overrides(cfg: dict[str, Any], environ: Mapping[str, str] | None = None) -> list[tuple[str, ...]]
def env_locked_paths(environ: Mapping[str, str] | None = None) -> list[str]
def env_var_for_path(path: tuple[str, ...] | str) -> str
```

`environ` is injectable so tests never mutate `os.environ`.

**Source A — explicit aliases.** A literal table:

| Env var | Config path |
|---|---|
| `CW_OIDC_ENABLED` | `app_auth.oidc.enabled` |
| `CW_OIDC_ISSUER` | `app_auth.oidc.issuer` |
| `CW_OIDC_CLIENT_ID` | `app_auth.oidc.client_id` |
| `CW_OIDC_CLIENT_SECRET` | `app_auth.oidc.client_secret` |
| `CW_OIDC_PUBLIC_BASE_URL` | `app_auth.oidc.public_base_url` |
| `CW_OIDC_GROUPS_CLAIM` | `app_auth.oidc.groups_claim` |
| `CW_OIDC_ALLOWED_GROUPS` | `app_auth.oidc.allowed_groups` |
| `CW_OIDC_SESSION_HOURS` | `app_auth.oidc.session_hours` |
| `CW_API_KEY` | `security.api_key` |

**Source B — generic.** `CW_CFG__<part>__<part>__…`: strip the prefix, split on `__`,
lowercase each part. `CW_CFG__app_auth__oidc__issuer` → `("app_auth", "oidc", "issuer")`.
Empty parts (from `___` or a trailing `__`) are dropped; a name that yields no parts is ignored.

An alias and a generic var naming the same path is a conflict; the alias wins and the collision
is logged at WARNING.

**Value parsing.** `json.loads(raw)`; on `json.JSONDecodeError` use `raw` verbatim as a string.
So:

| Env value | Parsed |
|---|---|
| `true` | `True` |
| `12` | `12` |
| `["admins","ops"]` | `["admins", "ops"]` |
| `https://auth.example.com/o/cw/` | `"https://auth.example.com/o/cw/"` |
| `admins,ops` | `"admins,ops"` (then comma-split by normalization, see §2) |

An empty env var (`CW_OIDC_ISSUER=`) parses to `""` and **is** an override — it locks the field
to empty rather than being treated as unset. Unset the variable to release the field.

`env_var_for_path` inverts the mapping for UI messaging: an aliased path returns its alias,
anything else returns the `CW_CFG__…` form.

### 2. Read path — `config_base.load_config`

`apply_env_overrides(cfg)` is called immediately after `_deep_merge(DEFAULT_CFG, user_cfg)` and
**before** the `_normalize_*` calls. Env values therefore go through exactly the same validation
and clamping as file values — no second code path:

- `CW_OIDC_SESSION_HOURS=9999` → clamped to `168`
- `CW_OIDC_ISSUER=" https://… "` → whitespace stripped, trailing slash preserved
- `CW_OIDC_PUBLIC_BASE_URL=https://cw.example.com/` → trailing slash dropped
- `CW_OIDC_GROUPS_CLAIM=` → falls back to `"groups"`

Values are written with the existing `_set_nested_value`, which creates intermediate dicts as
needed — so `CW_API_KEY` works even though `security.api_key` has no `DEFAULT_CFG` entry.

**One normalization change.** `_normalize_app_auth` currently wraps a bare-string
`allowed_groups` as a single-element list, so `CW_OIDC_ALLOWED_GROUPS=admins,ops` would become
`["admins,ops"]`. Change it to split a string value on commas and strip each part. The JSON list
form keeps working; an existing single-value string config is unaffected (a comma in an OIDC
group name is not a real case).

The applied paths are logged once per process at INFO, listing paths only — never values:

```
[CONFIG] INFO: Config locked by environment: app_auth.oidc.issuer, app_auth.oidc.client_secret, security.api_key
```

A module-level flag guards the log, since `load_config()` runs on nearly every request.

### 3. Write path — `config_base.save_config`

After the `_normalize_*` calls and before `_encrypt_secret_tree_stable`, every env-managed path
is reverted in the write payload:

- If the path exists in `prev_raw` (the on-disk JSON, already read by `save_config`), restore
  that value verbatim.
- Otherwise delete the key from the payload.

A new `_delete_nested_value(dst, path)` helper is needed; it prunes only the leaf, leaving
parent dicts in place.

Restoring an encrypted `enc:v1:` string verbatim is safe: `_encrypt_secret_tree_stable` will try
`_decrypt_secret(prev) == obj`, fail the comparison, and call `_encrypt_secret(obj)` — which
short-circuits on the `_ENC_PREFIX` and returns the string unchanged. No double encryption.

Net effect: `config.json` is byte-identical at env-managed paths across saves, and unsetting the
env var reverts the field to whatever the file said all along.

`save_config` also pops a top-level `_env_locked` key defensively, since `POST /api/config`
deep-merges the client payload into the current config and the UI receives that key.

### 4. API — `api/configAPI.py`

**`GET /api/config`** adds a top-level `_env_locked` array of dotted paths, injected after
`redact_config`:

```json
{ "app_auth": { … }, "_env_locked": ["app_auth.oidc.issuer", "app_auth.oidc.client_secret"] }
```

Secret values at those paths stay redacted as they are today; only the path list is new.

**`POST /api/config`** compares the incoming payload against the env-locked paths. Any locked
path present in the payload with a value differing from the effective config is dropped from the
merge and reported:

```json
{ "ok": true, "env_locked_ignored": ["app_auth.oidc.issuer"] }
```

The save still succeeds for everything else — a locked field is not an error, it is not the
client's to set.

**Other config-writing endpoints.** `POST /api/config` is not the only writer —
`/api/playback_progress/settings`, `/api/scrobbler/routes`, the anime-mapping endpoints, and the
OIDC callback all call `save_config` directly. The never-persisted guarantee lives in
`save_config` itself, so it holds for all of them without further change. Only the
`env_locked_ignored` *reporting* is specific to `POST /api/config`; the other endpoints silently
discard locked paths, which is acceptable because the fields they own are either not lockable
(list-indexed) or covered by the UI lock.

### 5. Frontend — lock mechanism

**`assets/helpers/env-lock.js` (new).** Exports `window.CW.applyEnvLocks(cfg)`:

1. Read `cfg._env_locked` (cached alongside the existing config cache).
2. For each element carrying `data-cfg-path`, resolve its effective path (see instance handling
   below) and test membership.
3. On a match: set `disabled`, add class `cw-env-locked`, and insert a "Set by environment" chip
   after the field with `title="Set by <ENV_VAR>"`. The env var name comes from a small
   client-side copy of the alias table, falling back to the `CW_CFG__` form.
4. On no match: remove the class, chip, and the `disabled` this function set — tracked with a
   `data-cfg-env-locked` marker so the function never re-enables a field some other code
   disabled for its own reasons.

Idempotent and safe to re-run. Called after every config hydration and after each settings pane
or modal render.

**Instance-scoped provider fields.** Provider credentials live under `plex.server_url` for the
default instance and `plex.instances.<name>.server_url` otherwise (see `_cwEnsureInstBlock` in
`settings-save.js`). Those inputs carry both attributes:

```html
<input id="plex_server_url" data-cfg-path="plex.server_url" data-cfg-instance-root="plex">
```

`applyEnvLocks` rewrites the path to `plex.instances.<selected>.server_url` when the selected
instance is not `default`, reading the selection the same way `_cwSelectedInst` does. It re-runs
on instance change.

**Annotation pass.** `data-cfg-path` is added to every config-bound input, select, and textarea:

| File | Fields |
|---|---|
| `ui_frontend.py` | `app_auth_*`, `ui_*`, `debug`, `trusted_proxies`, `sch*` (scheduling), `cw_*` (CrossWatch tracker) |
| `providers/auth/_auth_PLEX.py` | 10 |
| `providers/auth/_auth_JELLYFIN.py` | 12 |
| `providers/auth/_auth_EMBY.py` | 12 |
| `providers/auth/_auth_KODI.py` | 8 |
| `providers/auth/_auth_SIMKL.py` | 4 |
| `providers/auth/_auth_MDBLIST.py` | 3 |
| `providers/auth/_auth_TRAKT.py` | 3 |
| `providers/auth/_auth_TAUTULLI.py` | 3 |
| `providers/auth/_auth_ANILIST.py` | 2 |
| `providers/auth/_auth_TMDB.py` | 2 |
| `providers/auth/_auth_NUVIO.py` | 2 |
| `providers/auth/_auth_PUBLICMETADB.py` | 1 |
| `assets/js/modals/tls/index.js` | 7 (`ui.tls.*`) |
| `assets/js/playback_progress.js` | 1 (`pp-settings-timeout` → `playback_progress.provider_timeout_seconds`) |

Each path is verified against the field's actual write site in `settings-save.js` or the modal's
own save function — the element id is not a reliable guide (`app_auth_remember_enabled` writes
`app_auth.remember_session_enabled`).

**Explicitly out of scope, by construction:**

- `assets/js/modals/pair-config/index.js` (112 elements) — writes `pairs[i].*`. List indices are
  unaddressable from the environment, so these can never be locked.
- `assets/js/modals/scrobbler-route/index.js`, `scrobbler-webhook/index.js` — route records
  posted to `/api/scrobbler/routes`, keyed by id in a list. Same reason.
- Filter, search, and picker inputs that never touch config: `playlists.js`, `snapshots.js`,
  `watchlist.js`, `activity.js`, `editor.js`, `exporter`, `maintenance`, `manual-watched`,
  `analyzer`, `provider-cleanup`, `insight-settings`, `capture-compare`, `events`,
  the `pp-*` filter controls in `playback_progress.js`, `source-provider` /
  `target-provider` in `ui_frontend.py`.
- View-state toggles that gate other fields without being config themselves:
  `schEnabledToggle` and `schAdvEnabled` in `scheduler.js`.

These are recorded in `tests/data/env_lock_exclusions.txt` so the coverage test (§7) can tell
"deliberately not config-bound" from "someone forgot".

**Discarded-save feedback.** The `POST /api/config` caller in `settings-save.js` reads
`env_locked_ignored` and raises a toast naming the fields, so a save that silently dropped a
change now says which one and why.

**CSS.** `.cw-env-locked` and `.cw-env-chip` in `assets/crosswatch.css`, following the existing
disabled-field styling.

### 6. Frontend — OIDC settings section

OIDC has no UI today, so locking it would be theoretical. The app_auth settings pane in
`ui_frontend.py` gains an "Single sign-on (OIDC)" block:

| Field | Path | Control |
|---|---|---|
| Enable OIDC | `app_auth.oidc.enabled` | select true/false, matching `app_auth_remember_enabled` |
| Issuer URL | `app_auth.oidc.issuer` | text |
| Client ID | `app_auth.oidc.client_id` | text |
| Client secret | `app_auth.oidc.client_secret` | password, masked |
| Public base URL | `app_auth.oidc.public_base_url` | text |
| Groups claim | `app_auth.oidc.groups_claim` | text, placeholder `groups` |
| Allowed groups | `app_auth.oidc.allowed_groups` | text, comma-separated |
| Session hours | `app_auth.oidc.session_hours` | number, 1–168 |
| API key | `security.api_key` | password, masked |

Hydration goes in `settings-ui.js` beside the existing `app_auth` block; collection goes in
`settings-save.js`. Both secrets use the existing mask sentinel and `_cwApplySecret` convention,
so an untouched masked field is never written back as the literal mask. Empty `allowed_groups`
denies every OIDC login — the field carries that as help text, since it is the one setting whose
empty value is a deny rather than a default.

### 7. Tests

**`tests/test_config_env.py`**
- Value parsing per type: bool, int, JSON list, bare string, empty string.
- Alias form and generic form both resolve to the right path.
- Alias wins over a conflicting generic var.
- Malformed generic names (`CW_CFG__`, `CW_CFG____`) are ignored, not crashes.
- `env_var_for_path` returns the alias for aliased paths, `CW_CFG__…` otherwise.

**`tests/test_config_env_integration.py`**
- Env value beats a conflicting `config.json` value.
- Env value is still normalized: `session_hours=9999` → `168`, issuer whitespace stripped.
- `allowed_groups=admins,ops` → `["admins", "ops"]`; JSON list form also works.
- `save_config` leaves an env-managed path byte-identical in `config.json`, including the
  encrypted `client_secret` case.
- `save_config` deletes the key when the path was absent on disk.
- Unsetting the env var restores the file value on the next load.
- `_env_locked` is stripped on save.

**`tests/test_config_api_env_lock.py`**
- `_env_locked` present and correct in `GET /api/config`.
- `POST /api/config` reports `env_locked_ignored` and does not persist the locked change.
- A non-locked field in the same payload still saves.

**`tests/test_env_lock_coverage.py`**
- Regex-scans `ui_frontend.py`, `providers/auth/_auth_*.py`, and the annotated JS files for
  `<input|select|textarea …>` and asserts each element id either carries `data-cfg-path` or is
  listed in `tests/data/env_lock_exclusions.txt`. Fails when a new config field ships without an
  annotation or an explicit exclusion.

**`tests/test_oidc_config.py`** — extended for the comma-split `allowed_groups` case.

Existing suite must stay green; note the 6 pre-existing failures on `main` are unrelated.

### 8. Documentation

`README.md` gains an "Environment variables" section: the alias table, the `CW_CFG__` form and
its JSON-then-string rule, the never-persisted guarantee, and the limitations below. The
`docker-compose.yml` example gains commented-out OIDC variables.

## Limitations

- **No list indices.** `CW_CFG__pairs__0__enabled` does not work; `_set_nested_value` builds
  dicts only. Sync pairs and scrobbler routes are not env-configurable.
- **No leading-underscore keys.** Splitting on `__` cannot express `ui._autogen`. These are
  internal markers, not user settings.
- **Case.** Path parts are lowercased. Every current config key is lowercase snake_case; a
  mixed-case key added later would be unreachable generically and would need an alias.
- **Restart to change.** Env is read per `load_config()`, but the app caches config in places
  and CLAUDE.md already requires a restart for config changes.

## Risks

- **Generic override reaches secrets.** By design — that is the point for `client_secret` and
  provider tokens. Mitigated by never persisting them and by never logging values.
- **A stale `data-cfg-path` silently stops locking a field.** The coverage test catches a
  *missing* annotation but not a *wrong* one. Mitigated by verifying each path against its write
  site during the annotation pass, and by the server-side `env_locked_ignored` response, which is
  correct regardless of what the UI believes.
- **Empty-string override semantics.** `CW_OIDC_ISSUER=` locks the field to empty rather than
  releasing it. Documented in the README; the alternative (treat empty as unset) makes it
  impossible to deliberately blank a field from the environment.

## Alternatives considered

- **Env seeds `config.json` on first run.** Rejected: bakes secrets into the file, and removing
  the env var leaves a stale value behind — bad for GitOps.
- **Env only fills empty values.** Rejected: makes the environment non-authoritative, so a
  GitOps-managed deployment cannot be sure what it is running.
- **Central path→selector registry in JS instead of `data-cfg-path`.** Rejected: a registry
  drifts the moment someone adds a field, and nothing fails when it does. The attribute lives
  with the field and is statically checkable.
