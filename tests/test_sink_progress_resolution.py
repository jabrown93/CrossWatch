# tests/test_sink_progress_resolution.py
# CrossWatch - characterization tests for the p_send/action resolution logic
# shared (with real divergence, see module docstring) across the Trakt, SIMKL
# and MDBList scrobble sinks.
#
# These tests pin down CURRENT behavior of TraktSink.send / SimklSink.send /
# MDBListSink.send for the force_seek / start-floor / regress-tolerance
# progress computation plus the suppress-start / complete-at / demote-STOP-
# to-PAUSE logic. They exist as a safety net for a future extraction of a
# shared `resolve_send_progress` helper; see the accompanying report for why
# that extraction was not attempted in this pass (the divergence between
# Trakt and SIMKL/MDBList in this area is materially larger than "one extra
# branch" -- Trakt has two additional, send()-terminating early-return
# branches with their own state-mutation side effects that SIMKL/MDBList do
# not have at all).
from __future__ import annotations

from typing import Any

import pytest

import providers.scrobble.mdblist.sink as mdblist_mod
import providers.scrobble.simkl.sink as simkl_mod
import providers.scrobble.trakt.sink as trakt_mod
from providers.scrobble.scrobble import ScrobbleEvent

SK = "sess1"
MK = "tmdb:100"  # _mkey() output for ids={"tmdb": "100"}, media_type="movie" -- identical across all 3 sinks


def make_event(
    action: str,
    progress: int,
    *,
    media_type: str = "movie",
    raw: dict[str, Any] | None = None,
    session_key: str = SK,
    ids: dict[str, Any] | None = None,
) -> ScrobbleEvent:
    return ScrobbleEvent(
        action=action,  # type: ignore[arg-type]
        media_type=media_type,  # type: ignore[arg-type]
        ids=ids or {"tmdb": "100"},
        title="Test Movie",
        year=2020,
        season=None,
        number=None,
        progress=progress,
        account="user",
        server_uuid="srv-1",
        session_key=session_key,
        raw=raw or {},
    )


def make_cfg(kind: str, **overrides: Any) -> dict[str, Any]:
    """Build a minimal cfg for `kind` in {"trakt","simkl","mdblist"}.

    Per-sink getter fallback chains (verified by reading each sink's source,
    not assumed):
      - trakt reads scrobble.trakt.<key> directly.
      - simkl reads scrobble.simkl.<key>, falling back to scrobble.trakt.<key>.
      - mdblist's stop_pause_threshold/force_stop_at/complete_at/
        regress_tolerance_percent read scrobble.trakt.<key> directly (no
        scrobble.mdblist check at all); only progress_step checks
        scrobble.mdblist.<key> first.
    """
    settings = {
        "stop_pause_threshold": 85,
        "force_stop_at": 95,
        "complete_at": 0,
        "regress_tolerance_percent": 5,
        "progress_step": 1,
    }
    settings.update(overrides)
    scrobble: dict[str, Any] = {"watch": {"pause_debounce_seconds": 5, "suppress_start_at": 99}}
    if kind == "trakt":
        scrobble["trakt"] = dict(settings)
        return {"scrobble": scrobble, "trakt": {"client_id": "cid", "access_token": "tok"}}
    if kind == "simkl":
        scrobble["simkl"] = dict(settings)
        return {"scrobble": scrobble, "simkl": {"api_key": "key", "access_token": "tok"}}
    if kind == "mdblist":
        scrobble["trakt"] = dict(settings)
        return {"scrobble": scrobble, "mdblist": {"api_key": "key"}}
    raise ValueError(kind)


def _make_sink(monkeypatch: pytest.MonkeyPatch, kind: str):
    """Instantiate a sink with HTTP and recording fully mocked out.

    Returns (sink, captured, events):
      - captured: list of {"path", "body"} for every _send_http call that
        would have hit the network.
      - events["stop_recorded"]: list of kwargs passed to record_scrobble_event.
    """
    captured: list[dict[str, Any]] = []
    events: dict[str, list[dict[str, Any]]] = {"stop_recorded": []}

    def fake_record(ev: Any, **kw: Any) -> None:
        events["stop_recorded"].append(kw)

    if kind == "trakt":
        sink = trakt_mod.TraktSink(instance_id="default")

        def fake_send_http(path: str, body: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
            captured.append({"path": path, "body": body})
            return {"ok": True, "status": 201, "resp": {"action": path.rsplit("/", 1)[-1]}}

        monkeypatch.setattr(sink, "_send_http", fake_send_http)
        monkeypatch.setattr(trakt_mod, "record_scrobble_event", fake_record)
    elif kind == "simkl":
        sink = simkl_mod.SimklSink(instance_id="default")

        def fake_send_http(path: str, body: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
            captured.append({"path": path, "body": body})
            return {"ok": True, "status": 201, "resp": {"action": path.rsplit("/", 1)[-1]}}

        monkeypatch.setattr(sink, "_send_http", fake_send_http)
        monkeypatch.setattr(simkl_mod, "record_scrobble_event", fake_record)
    elif kind == "mdblist":
        sink = mdblist_mod.MDBListSink(instance_id="default")

        def fake_send_http(path: str, body: dict[str, Any], api_key: str, cfg: dict[str, Any]) -> dict[str, Any]:
            captured.append({"path": path, "body": body})
            return {"ok": True, "status": 201, "resp": {"action": path.rsplit("/", 1)[-1]}}

        monkeypatch.setattr(sink, "_send_http", fake_send_http)
        monkeypatch.setattr(mdblist_mod, "record_scrobble_event", fake_record)

        class _FakeAuth:
            def is_configured(self, *_a: Any, **_k: Any) -> bool:
                return True

        monkeypatch.setattr(mdblist_mod, "_provider_auth", lambda: _FakeAuth())
    else:
        raise ValueError(kind)

    return sink, captured, events


def _seed(sink: Any, session_key: str, mk: str, *, p_sess: int | None = None, p_glob: int | None = None, last_act: str | None = None) -> None:
    key = (session_key, mk)
    if p_sess is not None:
        sink._p_sess[key] = p_sess
    if p_glob is not None:
        sink._p_glob[mk] = p_glob
    if last_act is not None:
        sink._a_sess[key] = last_act


SINK_KINDS = ["trakt", "simkl", "mdblist"]


@pytest.mark.parametrize("kind", SINK_KINDS)
def test_normal_progress_advance(monkeypatch, config_base, kind):
    sink, captured, _events = _make_sink(monkeypatch, kind)
    _seed(sink, SK, MK, p_sess=30, last_act="pause")
    cfg = make_cfg(kind)
    sink.send(make_event("pause", 45), cfg)
    assert len(captured) == 1
    assert captured[0]["path"].endswith("/pause")
    assert captured[0]["body"]["progress"] == 45


@pytest.mark.parametrize("kind", SINK_KINDS)
def test_regression_within_tolerance_holds_prior_progress(monkeypatch, config_base, kind):
    # tol=5 (default); p_sess=50, p_now=47 -> regression of 3 is within
    # tolerance, so the sink holds at the prior (higher) session progress.
    sink, captured, _events = _make_sink(monkeypatch, kind)
    _seed(sink, SK, MK, p_sess=50, last_act="pause")
    cfg = make_cfg(kind)
    sink.send(make_event("pause", 47), cfg)
    assert len(captured) == 1
    assert captured[0]["body"]["progress"] == 50


@pytest.mark.parametrize("kind", SINK_KINDS)
def test_regression_beyond_tolerance_applies_lower_value(monkeypatch, config_base, kind):
    # p_sess=50, p_now=40 -> regression of 10 exceeds tol=5, so the lower
    # (actual) progress is sent.
    sink, captured, _events = _make_sink(monkeypatch, kind)
    _seed(sink, SK, MK, p_sess=50, last_act="pause")
    cfg = make_cfg(kind)
    sink.send(make_event("pause", 40), cfg)
    assert len(captured) == 1
    assert captured[0]["body"]["progress"] == 40


@pytest.mark.parametrize("kind", SINK_KINDS)
def test_force_seek_bypasses_tolerance(monkeypatch, config_base, kind):
    # _cw_seek=True makes p_send == p_now unconditionally for non-start
    # actions, even though p_sess=80 would otherwise hold/clamp a jump down to 20.
    sink, captured, _events = _make_sink(monkeypatch, kind)
    _seed(sink, SK, MK, p_sess=80, last_act="pause")
    cfg = make_cfg(kind)
    sink.send(make_event("pause", 20, raw={"_cw_seek": True}), cfg)
    assert len(captured) == 1
    assert captured[0]["body"]["progress"] == 20


@pytest.mark.parametrize("kind", SINK_KINDS)
def test_near_complete_stop_sends_and_records(monkeypatch, config_base, kind):
    # p_send=97 >= force_stop_at=95 -> action stays "stop", is sent, and a
    # completion event is recorded (gates auto-remove-from-watchlist).
    sink, captured, events = _make_sink(monkeypatch, kind)
    _seed(sink, SK, MK, p_sess=90, last_act="pause")
    cfg = make_cfg(kind)
    sink.send(make_event("stop", 97), cfg)
    assert len(captured) == 1
    assert captured[0]["path"].endswith("/stop")
    assert captured[0]["body"]["progress"] == 97
    assert len(events["stop_recorded"]) == 1
    assert events["stop_recorded"][0]["progress"] == 97


# --- Trakt-only branches ---------------------------------------------------
#
# Verified by reading all 3 files: Trakt has TWO extra send()-terminating
# early-return branches that SIMKL/MDBList do not have at all (not just "one
# extra 80%-cutoff branch" as assumed going in to this refactor):
#   1. STOP below stop_pause_threshold but >= the 80% Trakt scrobble cutoff
#      -> silently skipped (state recorded as "pause", nothing sent).
#   2. PAUSE at/above min(stop_pause_threshold, 80%) -> rejected outright
#      (Trakt's API 422s on /scrobble/pause above ~80%).
# STOP below both threshold and the 80% cutoff is demoted to PAUSE and still
# sent (this part *is* shared in spirit with SIMKL/MDBList's later
# jump-demote block, but the 80%-anchored trigger condition is Trakt-only).

def test_trakt_stop_between_cutoff_and_threshold_is_skipped_not_sent(monkeypatch, config_base):
    sink, captured, _events = _make_sink(monkeypatch, "trakt")
    cfg = make_cfg("trakt", stop_pause_threshold=90)
    sink.send(make_event("stop", 85, raw={"_cw_seek": True}), cfg)
    assert captured == []
    assert sink._a_sess[(SK, MK)] == "pause"
    assert sink._p_sess[(SK, MK)] == 85


def test_trakt_stop_below_cutoff_is_demoted_to_pause_and_sent(monkeypatch, config_base):
    sink, captured, _events = _make_sink(monkeypatch, "trakt")
    cfg = make_cfg("trakt", stop_pause_threshold=90)
    sink.send(make_event("stop", 70, raw={"_cw_seek": True}), cfg)
    assert len(captured) == 1
    assert captured[0]["path"].endswith("/pause")
    assert captured[0]["body"]["progress"] == 70


def test_trakt_pause_at_or_above_cutoff_is_rejected_not_sent(monkeypatch, config_base):
    sink, captured, _events = _make_sink(monkeypatch, "trakt")
    cfg = make_cfg("trakt", stop_pause_threshold=90)
    sink.send(make_event("pause", 85, raw={"_cw_seek": True}), cfg)
    assert captured == []
    assert sink._a_sess[(SK, MK)] == "pause"


@pytest.mark.parametrize("kind", ["simkl", "mdblist"])
def test_simkl_and_mdblist_send_stop_unchanged_where_trakt_would_skip(monkeypatch, config_base, kind):
    # Same cfg/progress as test_trakt_stop_between_cutoff_and_threshold_is_skipped_not_sent:
    # SIMKL/MDBList have no 80%-cutoff concept at all, so they send the STOP
    # unchanged instead of silently skipping it. This is the concrete proof
    # of the divergence documented above.
    sink, captured, _events = _make_sink(monkeypatch, kind)
    cfg = make_cfg(kind, stop_pause_threshold=90)
    sink.send(make_event("stop", 85, raw={"_cw_seek": True}), cfg)
    assert len(captured) == 1
    assert captured[0]["path"].endswith("/stop")
    assert captured[0]["body"]["progress"] == 85
