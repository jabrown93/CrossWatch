"""Persisting Plex accountID/accountUUID on activity rows.

Closes the gap left open in the security-advisory branch: an activity row that
stores only an account name can never satisfy an id:/uuid: allowlist entry, so a
profile scoped that way saw an empty feed.
"""
from __future__ import annotations

import sqlite3
from types import SimpleNamespace

from cw_platform.access_policy import media_account_scope_allows
from cw_platform.local_db import schema
from providers.scrobble.scrobble import account_identifiers

_RAW = {
    "NotificationContainer": {
        "PlaySessionStateNotification": [{"accountID": "42", "accountUUID": "AbC-123"}]
    }
}


def test_identifiers_extracted_from_a_raw_plex_notification() -> None:
    assert account_identifiers(_RAW) == ("42", "abc-123")


def test_missing_or_foreign_payload_yields_empty_identifiers() -> None:
    """Emby/Jellyfin carry no such block; empty means name-only matching."""
    assert account_identifiers(None) == ("", "")
    assert account_identifiers({"Item": {"Name": "x"}}) == ("", "")


def test_service_layer_records_the_identifiers() -> None:
    from services.activity import _account_identifiers

    assert _account_identifiers(SimpleNamespace(raw=_RAW)) == ("42", "abc-123")
    assert _account_identifiers(SimpleNamespace(raw=None)) == ("", "")
    assert _account_identifiers(object()) == ("", "")


def test_existing_database_gains_the_columns_and_reapply_is_safe(tmp_path) -> None:
    """apply_schema() is CREATE TABLE IF NOT EXISTS, so an already-created
    activity_events would never pick these up without an explicit ALTER."""
    conn = sqlite3.connect(tmp_path / "t.sqlite3")
    conn.execute(
        "CREATE TABLE activity_events (event_id TEXT PRIMARY KEY, kind TEXT NOT NULL, method TEXT,"
        " event TEXT, status TEXT NOT NULL DEFAULT 'ok', source TEXT, source_instance TEXT,"
        " target TEXT, target_instance TEXT, media_type TEXT, title TEXT, year INTEGER,"
        " season INTEGER, episode INTEGER, progress INTEGER, account TEXT, watched_at INTEGER,"
        " captured_at INTEGER, updated_at INTEGER NOT NULL)"
    )
    conn.commit()

    def cols() -> set[str]:
        return {str(r[1]) for r in conn.execute("PRAGMA table_info(activity_events)")}

    assert "account_id" not in cols()
    schema.apply_schema(conn)
    assert {"account_id", "account_uuid"} <= cols()
    schema.apply_schema(conn)
    assert len(cols()) == 21


_INSTANCES = {"PLEX": ["default"]}
_ID_ONLY = {"PLEX": {"default": ["id:42"]}}


def test_id_allowlist_now_matches_a_row_carrying_identifiers() -> None:
    """The point of the whole change: an id:-only allowlist is enforceable."""
    assert media_account_scope_allows(
        _ID_ONLY, "plex", "default", account="alice", account_id="42", name_only=True
    ) is True
    assert media_account_scope_allows(
        _ID_ONLY, "plex", "default", account="bob", account_id="7", name_only=True
    ) is False


def test_uuid_allowlist_matches_on_the_stored_uuid() -> None:
    allow = {"PLEX": {"default": ["uuid:abc-123"]}}
    assert media_account_scope_allows(
        allow, "plex", "default", account="alice", account_uuid="abc-123", name_only=True
    ) is True
    assert media_account_scope_allows(
        allow, "plex", "default", account="alice", account_uuid="other", name_only=True
    ) is False


def test_legacy_row_without_identifiers_still_denies() -> None:
    """Rows written before the migration keep the safe fallback rather than
    matching everyone."""
    assert media_account_scope_allows(
        _ID_ONLY, "plex", "default", account="alice", name_only=True
    ) is False


_WEBHOOK_RAW = {"event": "media.scrobble", "Account": {"id": 42, "uuid": "AbC-123", "title": "alice"}}


def test_identifiers_extracted_from_a_plex_webhook_payload() -> None:
    """The webhook path passes the raw payload, which carries a flat Account
    block rather than a PlaySessionStateNotification."""
    assert account_identifiers(_WEBHOOK_RAW) == ("42", "abc-123")


def test_playsessionstate_wins_when_both_shapes_are_present() -> None:
    both = dict(_WEBHOOK_RAW)
    both["NotificationContainer"] = _RAW["NotificationContainer"]
    assert account_identifiers(both) == ("42", "abc-123")


def test_account_block_without_identifiers_stays_empty() -> None:
    assert account_identifiers({"Account": {"title": "alice"}}) == ("", "")


def test_lost_alter_race_does_not_break_the_connect() -> None:
    """Connections are per thread and apply_schema() runs on each, so two can
    read the column as absent before either ALTER lands. The loser gets
    "duplicate column name" -- which must not fail the connect, because
    get_conn() turns a failed connect into None and silently drops the write.

    Driven directly rather than with threads: SQLite's write lock usually
    serialises the real thing, so a threaded test passes with or without the
    guard and proves nothing.
    """
    from cw_platform.local_db.schema import _ensure_column

    class _RaceConn:
        """Reports the column missing, then fails the ALTER as a rival would."""

        def __init__(self, error: str) -> None:
            self.error = error
            self.altered = 0

        def execute(self, sql: str):
            if sql.startswith("PRAGMA table_info"):
                return self
            self.altered += 1
            raise sqlite3.OperationalError(self.error)

        def fetchall(self):
            return [(0, "event_id", "TEXT", 0, None, 1)]

    conn = _RaceConn("duplicate column name: account_id")
    _ensure_column(conn, "activity_events", "account_id", "TEXT")  # must not raise
    assert conn.altered == 1

    # Any other failure is a real problem and must still surface.
    hard = _RaceConn("no such table: activity_events")
    try:
        _ensure_column(hard, "activity_events", "account_id", "TEXT")
    except sqlite3.OperationalError as e:
        assert "no such table" in str(e)
    else:
        raise AssertionError("a non-duplicate OperationalError must propagate")


def test_same_display_name_different_accounts_are_not_merged() -> None:
    """_group_route_fanout merges rows within the window; without the
    identifiers two accounts sharing a display name would collapse into one
    group and be filtered as a single row."""
    from services.activity import _group_key

    base = {"kind": "scrobble", "event": "scrobble_stop", "source": "plex",
            "media_type": "movie", "title": "Dune", "account": "chris"}
    assert _group_key({**base, "account_id": "42"}) != _group_key({**base, "account_id": "7"})
    assert _group_key({**base, "account_uuid": "a"}) != _group_key({**base, "account_uuid": "b"})
    assert _group_key({**base, "account_id": "42"}) == _group_key({**base, "account_id": "42"})
    # Rows predating the migration carry no identifiers and group as before.
    assert _group_key(dict(base)) == _group_key(dict(base))


def test_identifiers_come_from_the_same_entry_the_event_uses() -> None:
    """A payload can carry several PlaySessionStateNotification entries.
    from_plex_pssn() builds the event from the highest-scoring one, so reading
    identifiers off entry zero would staple one session's media to another
    session's account and attribute the row to the wrong profile."""
    from providers.scrobble.scrobble import from_plex_pssn

    thin = {"accountID": "7", "accountUUID": "bob-uuid"}
    rich = {
        "accountID": "42", "accountUUID": "AbC-123",
        "sessionKey": "1", "ratingKey": "100", "guid": "plex://movie/x",
        "state": "playing", "viewOffset": 1000, "duration": 5000,
        "title": "Dune", "type": "movie",
    }
    payload = {"PlaySessionStateNotification": [thin, rich]}

    # The event is built from `rich` even though `thin` sorts first...
    event = from_plex_pssn(payload)
    assert event is not None and event.title == "Dune"
    # ...so the identifiers must be rich's too.
    assert account_identifiers(payload) == ("42", "abc-123")


def test_single_entry_payload_is_unaffected() -> None:
    payload = {"PlaySessionStateNotification": [{"accountID": "9", "accountUUID": "Z"}]}
    assert account_identifiers(payload) == ("9", "z")


def test_flat_watcher_alert_keeps_the_resolved_identifiers() -> None:
    """A flat Plex alert has no PlaySessionStateNotification, but the watcher
    stamps the identity its session lookup resolved. Without reading it, that
    identity never reaches the activity row and an id:-scoped profile loses the event."""
    raw = {"_type": "playing", "_cw_session_identity": {"name": "alice", "account_id": "42", "account_uuid": "ABC-123"}}
    assert account_identifiers(raw) == ("42", "abc-123")


def test_session_identity_gaps_fall_back_to_the_payload() -> None:
    raw = {"_cw_session_identity": {"account_id": "42"}, "Account": {"uuid": "abc-123"}}
    assert account_identifiers(raw) == ("42", "abc-123")


def test_account_block_fills_only_the_identifier_pssn_lacks() -> None:
    """A PSSN can carry accountID while only the stamped/webhook Account block
    knows the uuid. An all-or-nothing fallback dropped the half that existed."""
    payload = {
        "PlaySessionStateNotification": [{"accountID": "42", "sessionKey": "1"}],
        "Account": {"id": "999", "uuid": "AbC-123"},
    }
    # PSSN wins for id; Account supplies the missing uuid.
    assert account_identifiers(payload) == ("42", "abc-123")


def test_account_block_fills_a_missing_id() -> None:
    payload = {
        "PlaySessionStateNotification": [{"accountUUID": "PSSN-UUID", "sessionKey": "1"}],
        "Account": {"id": "42"},
    }
    assert account_identifiers(payload) == ("42", "pssn-uuid")


def test_event_id_separates_accounts_sharing_a_title_and_second() -> None:
    """save_event() upserts on event_id, so two accounts finishing the same
    title through the same route in the same second must not collide -- the
    second would overwrite the first before profile filtering ever ran."""
    from services.activity import _event_id

    base = {
        "kind": "scrobble", "method": "watcher", "event": "scrobble_stop",
        "status": "ok", "source": "plex", "source_instance": "default",
        "target": "trakt", "target_instance": "default",
        "media_type": "movie", "title": "Dune", "watched_at": 1000, "ids": {},
    }
    assert _event_id({**base, "account_id": "42"}) != _event_id({**base, "account_id": "7"})
    assert _event_id({**base, "account_uuid": "a"}) != _event_id({**base, "account_uuid": "b"})
    assert _event_id({**base, "account": "alice"}) != _event_id({**base, "account": "bob"})
    assert _event_id({**base, "account_id": "42"}) == _event_id({**base, "account_id": "42"})
