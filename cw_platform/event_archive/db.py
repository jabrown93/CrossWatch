# cw_platform/event_archive/db.py
# CrossWatch - Event archive database path and connection management
# Copyright (c) 2025-2026 CrossWatch / Cenodude (https://github.com/cenodude/CrossWatch)
from __future__ import annotations

import logging
import os
import sqlite3
import threading
from pathlib import Path

_LOG = logging.getLogger("crosswatch.event_archive")

_LOCK = threading.RLock()
# One connection per thread. Sharing a single connection across the sync run,
# the webhook handlers and the scrobble watchers interleaves their implicit
# transactions -- "cannot start a transaction within a transaction" and lost
# writes, all swallowed by the recorders' broad excepts. WAL lets the separate
# connections write concurrently, and busy_timeout absorbs the contention.
_LOCAL = threading.local()
# Registry so close_conn() can still drop every handle, not just the caller's.
_CONNS: dict[int, sqlite3.Connection] = {}
_GENERATION = 0

_MEMORY_URI = "file:crosswatch_events_mem?mode=memory&cache=shared"


class EventArchiveError(Exception):
    pass


def _config_base() -> Path:
    try:
        from ..config_base import CONFIG_BASE
        return CONFIG_BASE()
    except Exception:
        if Path("/app").exists():
            return Path("/config")
        return Path(__file__).resolve().parents[2]


def events_db_path() -> Path:
    env = (os.getenv("CROSSWATCH_EVENTS_DB") or "").strip()
    if env:
        return Path(env)
    return _config_base() / ".cw_databases" / "events.sqlite3"


def _apply_pragmas(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    for pragma in (
        "PRAGMA journal_mode=WAL",
        "PRAGMA synchronous=NORMAL",
        "PRAGMA busy_timeout=5000",
        "PRAGMA foreign_keys=ON",
    ):
        try:
            cur.execute(pragma)
        except Exception:
            pass
    cur.close()


def connect(path: str | os.PathLike[str] | None = None) -> sqlite3.Connection:
    p = Path(path) if path is not None else events_db_path()
    if str(p) != ":memory:":
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            raise EventArchiveError(f"cannot create db dir {p.parent}: {exc}") from exc
    if str(p) == ":memory:":
        # Connections are per-thread, so a plain ":memory:" would hand every
        # thread its own empty database. Shared-cache keeps the escape hatch
        # behaving like the one archive the rest of the code assumes.
        conn = sqlite3.connect(_MEMORY_URI, timeout=5.0, check_same_thread=False, uri=True)
    else:
        conn = sqlite3.connect(str(p), timeout=5.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        _apply_pragmas(conn)
        from .schema import apply_schema
        apply_schema(conn)
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        raise
    return conn


def _forget_local() -> None:
    conn = getattr(_LOCAL, "conn", None)
    if conn is not None:
        with _LOCK:
            _CONNS.pop(threading.get_ident(), None)
        try:
            conn.close()
        except Exception:
            pass
    _LOCAL.conn = None
    _LOCAL.path = None


def get_conn() -> sqlite3.Connection | None:
    want = str(events_db_path())
    conn = getattr(_LOCAL, "conn", None)
    if conn is not None:
        stale = getattr(_LOCAL, "generation", -1) != _GENERATION or getattr(_LOCAL, "path", None) != want
        if not stale and (want == ":memory:" or Path(want).exists()):
            return conn
        if not stale:
            _LOG.warning("event archive database file missing; recreating %s", want)
        _forget_local()
    # Retry if close_conn() lands between connect() and registration: rebuild()
    # unlinks the file straight after, so a handle opened in that window points
    # at a dead inode while looking current.
    for _ in range(3):
        generation = _GENERATION
        try:
            conn = connect(want)
        except Exception as exc:
            _LOG.warning("event archive unavailable: %s", exc)
            _LOCAL.conn = None
            _LOCAL.path = None
            return None
        with _LOCK:
            if _GENERATION == generation:
                _prune_dead_locked()
                _CONNS[threading.get_ident()] = conn
                _LOCAL.generation = generation
                _LOCAL.conn = conn
                _LOCAL.path = want
                return conn
        try:
            conn.close()
        except Exception:
            pass
    _LOG.warning("event archive connection kept being invalidated: %s", want)
    _LOCAL.conn = None
    _LOCAL.path = None
    return None


def _prune_dead_locked() -> None:
    """Drop registry entries for threads that exited without closing.

    Callers hold _LOCK. Short-lived request threads would otherwise leak a
    connection each; the owning thread is gone, so nothing can be mid-statement.
    """
    alive = {t.ident for t in threading.enumerate()}
    for ident in [i for i in _CONNS if i not in alive]:
        conn = _CONNS.pop(ident, None)
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass


def close_conn() -> None:
    """Drop every thread's connection, not just the caller's.

    rebuild() unlinks the database file right after this returns, so a handle
    left open in a watcher thread would keep writing into the dead inode. The
    generation bump makes those threads reconnect on their next get_conn()
    instead of reusing a closed handle.
    """
    global _GENERATION
    with _LOCK:
        _GENERATION += 1
        for conn in _CONNS.values():
            try:
                conn.close()
            except Exception:
                pass
        _CONNS.clear()
    _LOCAL.conn = None
    _LOCAL.path = None
