## [1.3.4](https://github.com/jabrown93/CrossWatch/compare/v1.3.3...v1.3.4) (2026-08-19)


### Bug Fixes

* **punchplay:** do not throttle the first forced token refresh after boot ([#84](https://github.com/jabrown93/CrossWatch/issues/84)) ([32a27d1](https://github.com/jabrown93/CrossWatch/commit/32a27d12a2cbb96202599933897daf756d0aba57))

## [1.3.3](https://github.com/jabrown93/CrossWatch/compare/v1.3.2...v1.3.3) (2026-08-17)


### Bug Fixes

* **deps:** update dhi.io/python docker tag ([4426dcb](https://github.com/jabrown93/CrossWatch/commit/4426dcb80e3af76f3bae3f8de1e97fe2062dc6ad))
* **deps:** update digest updates ([fbbacac](https://github.com/jabrown93/CrossWatch/commit/fbbacac6ff18aea8dbd658ff3531af42c67d5d7f))
* **deps:** update digest updates ([b3ee715](https://github.com/jabrown93/CrossWatch/commit/b3ee71573aaaf633db3d5985c67fd3f768610565))
* **deps:** update digest updates ([554440e](https://github.com/jabrown93/CrossWatch/commit/554440e56920bcc5a599ac387055800f6dad8031))

## [1.3.2](https://github.com/jabrown93/CrossWatch/compare/v1.3.1...v1.3.2) (2026-08-10)


### Bug Fixes

* **deps:** update dhi.io/python:3.14.6-alpine3.24 docker digest to be6d656 ([e193d34](https://github.com/jabrown93/CrossWatch/commit/e193d3406daf7789000837cd90afdc7af0fcca2c))
* **deps:** update digest updates ([dfb12a3](https://github.com/jabrown93/CrossWatch/commit/dfb12a315d4968aaa80abaf8c0286351d246448a))

## [1.3.1](https://github.com/jabrown93/CrossWatch/compare/v1.3.0...v1.3.1) (2026-08-03)


### Bug Fixes

* **deps:** pin dependencies ([1ba09d0](https://github.com/jabrown93/CrossWatch/commit/1ba09d0ef796362f27cf8f37a4a21cff476c18f0))

# [1.3.0](https://github.com/jabrown93/CrossWatch/compare/v1.2.1...v1.3.0) (2026-07-31)


### Features

* **config:** accept environment variables for OIDC and any config path ([#74](https://github.com/jabrown93/CrossWatch/issues/74)) ([72a4428](https://github.com/jabrown93/CrossWatch/commit/72a4428c884f9c8eebf1d7e100f467a8aefa2a11))

## [1.2.1](https://github.com/jabrown93/CrossWatch/compare/v1.2.0...v1.2.1) (2026-07-31)


### Bug Fixes

* **license:** ship modification notice and fork labels in the image ([#73](https://github.com/jabrown93/CrossWatch/issues/73)) ([a09b062](https://github.com/jabrown93/CrossWatch/commit/a09b06291955c4ed825d6501c1ff858091ac3d1f))

# [1.2.0](https://github.com/jabrown93/CrossWatch/compare/v1.1.6...v1.2.0) (2026-07-28)


### Features

* **auth:** OIDC (Authentik) SSO + static API key ([#72](https://github.com/jabrown93/CrossWatch/issues/72)) ([d947b3b](https://github.com/jabrown93/CrossWatch/commit/d947b3bccb4e4a85bc8bf0827bab2dcf46fa198a))

## [1.1.6](https://github.com/jabrown93/CrossWatch/compare/v1.1.5...v1.1.6) (2026-07-28)


### Bug Fixes

* **sse:** generation-scoped resume cursor for summary stream ([#71](https://github.com/jabrown93/CrossWatch/issues/71)) ([be43a0f](https://github.com/jabrown93/CrossWatch/commit/be43a0febb2c9489204173a8c05112fec67397ee))
* **ui:** stop unbounded event listener and interval accumulation ([#66](https://github.com/jabrown93/CrossWatch/issues/66)) ([90e3922](https://github.com/jabrown93/CrossWatch/commit/90e3922524b351e4741022c371f26aa72c26bb9a))

## [1.1.5](https://github.com/jabrown93/CrossWatch/compare/v1.1.4...v1.1.5) (2026-07-28)


### Bug Fixes

* **event-archive:** isolate connections per thread and hash provider instances ([#65](https://github.com/jabrown93/CrossWatch/issues/65)) ([d657451](https://github.com/jabrown93/CrossWatch/commit/d6574515a4d438ff944bbfcd0d73df4f7572f0e9))

## [1.1.4](https://github.com/jabrown93/CrossWatch/compare/v1.1.3...v1.1.4) (2026-07-28)


### Performance Improvements

* **sse:** resumable summary stream and reconnect backoff ([#68](https://github.com/jabrown93/CrossWatch/issues/68)) ([23effc6](https://github.com/jabrown93/CrossWatch/commit/23effc6902c3630f3848d4000556839739d21dfa))

## [1.1.3](https://github.com/jabrown93/CrossWatch/compare/v1.1.2...v1.1.3) (2026-07-28)


### Bug Fixes

* **logs:** stop unbounded log-buffer growth from reader endpoints ([#70](https://github.com/jabrown93/CrossWatch/issues/70)) ([a1cea79](https://github.com/jabrown93/CrossWatch/commit/a1cea79d72d3a6717109a3a2ba504c973eb31636))

## [1.1.2](https://github.com/jabrown93/CrossWatch/compare/v1.1.1...v1.1.2) (2026-07-28)


### Performance Improvements

* **ui:** stop hidden-tab poll churn and redundant lane rebuilds ([#67](https://github.com/jabrown93/CrossWatch/issues/67)) ([62ab99c](https://github.com/jabrown93/CrossWatch/commit/62ab99c11b0a1561acf9dade522311c05bc25f14))

## [1.1.1](https://github.com/jabrown93/CrossWatch/compare/v1.1.0...v1.1.1) (2026-07-28)


### Performance Improvements

* **ui:** reduce background timer wakeups and redundant refresh work ([#69](https://github.com/jabrown93/CrossWatch/issues/69)) ([a8ac8b1](https://github.com/jabrown93/CrossWatch/commit/a8ac8b1d09825b17e073283ce199fedca9d5c664))

# [1.1.0](https://github.com/jabrown93/CrossWatch/compare/v1.0.1...v1.1.0) (2026-07-28)


### Features

* sync with upstream cenodude/CrossWatch v0.10.6 ([351cb36](https://github.com/jabrown93/CrossWatch/commit/351cb36fdb2acb19ab8e753d3e4f6b8e2a751e98)), closes [#40](https://github.com/jabrown93/CrossWatch/issues/40) [#58](https://github.com/jabrown93/CrossWatch/issues/58) [#59](https://github.com/jabrown93/CrossWatch/issues/59) [#57](https://github.com/jabrown93/CrossWatch/issues/57) [#385](https://github.com/jabrown93/CrossWatch/issues/385) [#426](https://github.com/jabrown93/CrossWatch/issues/426) [#395](https://github.com/jabrown93/CrossWatch/issues/395) [pre-#426](https://github.com/pre-/issues/426)

## [1.0.1](https://github.com/jabrown93/CrossWatch/compare/v1.0.0...v1.0.1) (2026-07-27)


### Bug Fixes

* **deps:** update dependency com.android.tools.build:gradle to v9.3.1 ([fc3b57b](https://github.com/jabrown93/CrossWatch/commit/fc3b57b71435d83518f59f4b494a578e7d64f0e7))

# [1.0.0](https://github.com/jabrown93/CrossWatch/compare/v0.9.15...v1.0.0) (2026-07-20)


* Security hardening: fail-closed webhooks, real SSRF guard, mandatory setup, dead-code cleanup ([#53](https://github.com/jabrown93/CrossWatch/issues/53)) ([53579da](https://github.com/jabrown93/CrossWatch/commit/53579dab7f0dabf857d702d8633710884e0689d2))


### Features

* automate versioning and releases via semantic-release ([#52](https://github.com/jabrown93/CrossWatch/issues/52)) ([9f60e71](https://github.com/jabrown93/CrossWatch/commit/9f60e71058925ca4a90a083eeb70407a4cd9544d))


### BREAKING CHANGES

* a config save with a plex/jellyfin/emby/tautulli server
URL pointing at a metadata or link-local address is now rejected (400)
instead of silently saved with a log line.

* fix: webhook payload auth fails closed instead of open

providers/webhooks/_utils.py::verify_webhook_secret and
plextrakt.py::_verify_signature both returned True (accept) when no
webhook_secret was configured for that provider — an unset secret meant
Plex/Emby/Jellyfin scrobble webhooks were authenticated by nothing more than
a WARN log. Flip both to return False: a webhook is now rejected until an
admin configures a secret.

The three webhook routes in api/scrobbleAPI.py previously mapped every
outcome — including a rejected secret/signature — to HTTP 200 with
{"ok": false} in the body, so a fail-closed check alone wouldn't have been
visible at the transport level. Added webhook_result_status() in
providers/webhooks/_utils.py (invalid_webhook_secret / invalid_signature ->
401, everything else stays 200 as before) and wired it into all three
routes; a rejected request now short-circuits before scheduler/activity
event emission and returns 401.

This does not change the URL-path webhook token layer
(_require_webhook_token in api/scrobbleAPI.py), which already failed closed.
* existing installs with scrobble webhooks enabled and no
webhook_secret set will stop receiving scrobbles until a secret is
configured on both CrossWatch and the sending media server.

* test: fix mandatory-setup test, add fresh-install regression coverage

setup_lock_required()/auth_required() (api/appAuthAPI.py) already enforce
mandatory credential setup at runtime: _normalize_app_auth() (called by
both load_config and save_config) forces app_auth.enabled=True
unconditionally, and sets reset_required=True if a config was saved with
enabled=False while credentials were already configured — auth cannot be
silently opted out of once set up.

The deselected test asserted the opposite of this: it hand-built a config
with enabled=False and valid credentials, *bypassing* normalization, and
expected setup_lock_required() to return False. That state can't occur
through the real load/save path — if it did, normalization would set
reset_required=True and correctly keep the lock engaged. The test encoded
the old, pre-mandatory-auth opt-in semantics.

Replaced it with two tests that exercise the real, reachable states via
_normalize_app_auth() directly:
- a fresh install with no credentials configured must be setup-locked
  (the direct "mandatory setup" guarantee), and
- once credentials are configured, enabled, and no reset is pending, the
  lock is released.

Removed the now-unnecessary --deselect for this test from ci.yml; it was a
fork-local test bug, not one of the three pre-existing upstream bugs the
other deselects track.

* fix: close SSRF guard bypasses flagged in PR review

The SSRF guard added in 8b37207 only ran inside api_config_save.
/api/jellyfin/login, /api/emby/login, and /api/tautulli/save each make a
live outbound request to the attacker-supplied server before that guard is
ever reached, so an authenticated request could still reach a metadata or
link-local address through those routes. Validate immediately before each
of those calls instead.

Also close a narrow bypass in _is_dangerous_ip: an IPv4-mapped IPv6 literal
(e.g. ::ffff:100.100.100.200) wrapped a blocked address but wasn't unwrapped
before the link-local/blocklist check.

* fix: apply SSRF guard to per-instance provider server URLs too

api_config_save only checked the default plex/jellyfin/emby/tautulli
server fields. A non-default instance's server is stored under
provider.instances.<id> and gets promoted to the active config by
build_provider_config_view() for probes, manual ops, and sync — so it
carried the same SSRF risk without being validated. Iterate every
instance block for each of the four fields, not just the default one.

* Revert "fix: webhook payload auth fails closed instead of open"

This reverts commit 27339d2bb5b1a28a75649fe9278ad49ad78835ef.

* fix: revalidate redirect targets during SSRF-guarded outbound requests

assert_server_url_safe() only checked the URL once at login/save time, but
the actual Jellyfin/Emby login requests and the Tautulli credential check
used requests' default redirect-following behavior. A server that passes
validation could still 302 the real request to a metadata/link-local
address (e.g. 169.254.169.254) and have it followed unchecked.

Added guarded_request() in cw_platform/url_validation.py: disables
automatic redirect-following and instead validates + follows each hop
manually via assert_server_url_safe(), capped at 5 redirects. Wired into
the two _auth_JELLYFIN.py/_auth_EMBY.py request call sites and
_validate_tautulli_credentials(), which covers both /api/tautulli/save
and /api/tautulli/status?verify=1.

* fix: reject cross-host redirects in SSRF-guarded requests

guarded_request() re-validated each redirect hop against the SSRF
blocklist but re-sent the original kwargs unchanged, so a redirect to a
merely *routable* host still handed that host the request's credentials:
Jellyfin/Emby send the user's password as the POST body, Tautulli sends
its apikey as a query param, and the Users/Me probes send provider tokens
as headers. requests' own redirect handling strips only the Authorization
header, which covers none of those, so mirroring it isn't sufficient here.

Refuse any hop that leaves the configured host instead of trying to
sanitise it. Port changes stay allowed (same machine) and http->https
upgrades still work, since that's the common real-world probe; an
https->http downgrade is refused because it would put the same
credentials on the wire in the clear. A legitimate proxy that redirects
across hostnames now needs the final URL configured directly, which is an
actionable failure rather than a silent credential leak.

Also reproduce requests' method/body semantics for the same-host hops we
do follow: guarded_request drives redirects by hand, so Session's
rebuild_method()/resolve_redirects() never run. Previously only 303 was
handled, leaving a 302'd POST to be replayed with its body instead of
becoming a bodyless GET.

Regression tests cover the credential-leak path (asserting the redirect
target is never contacted at all), a cross-host hop to an otherwise-safe
public host, the downgrade/upgrade cases, and 302-vs-307 method handling.
