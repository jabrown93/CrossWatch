# cw_platform/event_archive/db.py
# CrossWatch - Event archive database path and connection management
# Copyright (c) 2025-2026 CrossWatch / Cenodude (https://github.com/cenodude/CrossWatch)
from __future__ import annotations

import logging
import os
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
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
# Count of active suspended() contexts; connections are barred while nonzero.
# A boolean would let the first of two overlapping rebuilds lift the suspension
# while the other is still unlinking the database files.
_SUSPEND_DEPTH = 0

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
    # Retry if the generation moves between connect() and registration: a handle
    # opened in that window can point at an inode suspended() is about to unlink,
    # while still looking current.
    for _ in range(3):
        with _LOCK:
            if _SUSPEND_DEPTH:
                _LOCAL.conn = None
                _LOCAL.path = None
                return None
            generation = _GENERATION
        try:
            conn = connect(want)
        except Exception as exc:
            _LOG.warning("event archive unavailable: %s", exc)
            _LOCAL.conn = None
            _LOCAL.path = None
            return None
        with _LOCK:
            if not _SUSPEND_DEPTH and _GENERATION == generation:
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


def _invalidate_locked() -> None:
    """Close every registered connection and make outstanding handles stale.

    Callers hold _LOCK. The generation bump is what stops a thread that is
    holding a now-closed handle from reusing it on its next get_conn().
    """
    global _GENERATION
    _GENERATION += 1
    for conn in _CONNS.values():
        try:
            conn.close()
        except Exception:
            pass
    _CONNS.clear()


def close_conn() -> None:
    """Drop every thread's connection, not just the caller's."""
    with _LOCK:
        _invalidate_locked()
    _LOCAL.conn = None
    _LOCAL.path = None


@contextmanager
def suspended() -> Iterator[None]:
    """Bar connection creation for the duration of the block.

    close_conn() alone is not enough for rebuild(): it unlinks the database
    files a moment later, and a watcher calling get_conn() in between would
    register a connection against the doomed inode carrying the current
    generation. Nothing would mark it stale afterwards -- rebuild recreates the
    file, so the existence check passes -- and that thread's writes would
    disappear into the deleted inode.

    get_conn() returns None while suspended. Recorders already treat that as
    "archive unavailable" and skip the write, which is the correct outcome
    while the archive is being replaced.
    """
    global _SUSPEND_DEPTH
    with _LOCK:
        _SUSPEND_DEPTH += 1
        _invalidate_locked()
    _LOCAL.conn = None
    _LOCAL.path = None
    try:
        yield
    finally:
        with _LOCK:
            # Bump again so anything opened against the old files during the
            # block is treated as stale rather than current.
            _invalidate_locked()
            _SUSPEND_DEPTH -= 1
