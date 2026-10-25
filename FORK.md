# Fork notes

Unofficial fork of [cenodude/CrossWatch](https://github.com/cenodude/CrossWatch). This file is the
contract for keeping it close to upstream: what differs, why, and how to sync.

## Syncing upstream

`main` is squash-only with signed commits, so upstream history never lands here and git cannot
find the merge base by itself. `.upstream-sync` records the last upstream commit already merged.

```bash
scripts/sync-upstream.sh            # branch from origin/main, merge upstream/main
# resolve conflicts (policy below), run the tests, git add
scripts/sync-upstream.sh --finish   # one commit on top of origin/main; updates .upstream-sync
```

Open a PR from the branch. `.github/workflows/upstream-sync.yml` does this weekly: a clean merge
becomes a PR, a conflicting one becomes a tracking issue.

Never edit `.upstream-sync` by hand to a commit that has not actually been merged; the next sync
would silently drop everything before it.

To tell merge regressions from upstream's own failures, run the suite on a pristine checkout of
the target upstream commit and compare the failure lists. CI deselects the tests in
`.github/pytest-deselect.txt`: one section for upstream tests that contradict a fork decision,
one regenerated each sync from the pristine upstream failures.

### Conflict policy

1. **Upstream's code shape wins.** Fork-only refactors of upstream code are not kept. Re-apply the
   fork *behavior* as the smallest patch on upstream's version, marked with a `# Fork:` (or
   `// Fork:`) comment so the next conflict is obvious.
2. **Keep fork behavior listed below.** Anything not listed is upstream's call.
3. **Fork-owned paths** (`.github/workflows/`, `Dockerfile`, `requirements*.{in,txt}`) keep the fork
   version; the script restores workflow changes automatically. Port upstream changes there
   deliberately (e.g. new Python deps go into `requirements.in`, then `uv pip compile`).
4. New behavioral conflicts the policy does not cover: record a decision here before merging.

## Fork differences

| Area | Behavior | Where |
| --- | --- | --- |
| Container | Shell-less, nonroot DHI Python runtime; hash-locked deps. No `entrypoint.sh`, so `CW_CLI_ONLY` and `run-once` are unsupported. CLI: `python /app/cli/cw.py`. | `Dockerfile` |
| Auth | OIDC login with auto-redirect; first-setup token gate. | `services/authOidc.py`, `api/appAuthAPI.py` |
| Config | Any setting from the environment (`CW_OIDC_*`, `CW_CFG__a__b`); env values never written to `config.json` and shown locked in the UI. | `cw_platform/config_env.py`, `assets/helpers/env-lock.js` |
| SSRF | Outbound requests to user-supplied servers and IdP avatar URLs go through `guarded_request`, re-validating every redirect hop. | `cw_platform/url_validation.py` |
| Sync writes | Non-idempotent writes are attempted once (429 excepted): a timed-out write may have landed, and replaying duplicates history entries. | `_applier._retry`, `_mod_common.request_with_retries` |
| Mass delete | `drop_guard` on and `allow_mass_delete` off by default; guard errors block rather than allow. | `_pairs_oneway.py`, `_pairs_twoway.py`, `_pairs_massdelete.py` |
| Local DB | `suspended()` around restores/rebuilds, `SCHEMA_LOCK` around schema setup, shared-cache `:memory:`. | `cw_platform/local_db/db.py` |
| Scheduler | A failing tick is logged and retried instead of ending the scheduler thread. | `services/scheduling.py` |
| SSE | Summary stream resumes from `Last-Event-ID` instead of replaying the buffer. | `api/syncAPI.py` |
| Logging | Trakt refresh failures log status plus allowlisted OAuth error. | `providers/auth/_auth_TRAKT.py` |
| State dirs | Provider state dirs are created on first write, not at import. | `providers/sync/*/_common.py` |

## Decisions

Dated so a later sync can revisit them.

- **2026-10 sync (upstream #798 → #1569)**
  - Ship upstream's `cw` CLI; no shell-based container modes.
  - Local DB: upstream implementation plus the fork's suspension, schema lock, and `:memory:` sharing.
  - Keep single-attempt non-idempotent writes.
  - Drop fork-only refactors (policy 1 above).
  - Drop the static `CW_API_KEY`; use upstream's scoped, revocable API tokens.
  - Adopt upstream's TMDB-first canonical keys (fork was IMDb-first). Keeping IMDb-first broke 244
    upstream tests and would keep costing every sync. Existing state is rekeyed once on first run.
  - Drop upstream's `ghcr-pulls-badge` workflow (publishes upstream's numbers).
  - New upstream form fields (42) are listed in `tests/data/env_lock_exclusions.txt` rather than
    annotated with `data-cfg-path`; env overrides still apply, the UI just does not show them locked.
  - Upstream node tests `setup-wizard.test.mjs` (2) fail on the setup-token gate; CI does not run
    node tests.
