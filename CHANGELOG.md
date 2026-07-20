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
