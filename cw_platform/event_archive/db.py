# cw_platform/event_archive/db.py
# CrossWatch - Event archive database access
# Copyright (c) 2025-2026 CrossWatch / Cenodude (https://github.com/cenodude/CrossWatch)
from __future__ import annotations

import os
import sqlite3
import threading
from pathlib import Path

from ..local_db.db import (
    SCHEMA_LOCK,
    LocalDatabaseError,
    close_conn,
    connect as _connect,
    crosswatch_db_path,
    get_conn as _get_conn,
    suspended,
)

EventArchiveError = LocalDatabaseError

# Connection the event schema was last applied to, per thread. get_conn() hands
# back the same per-thread connection on every call, so this skips redoing the
# schema on every write.
_APPLIED = threading.local()

__all__ = [
    "EventArchiveError",
    "close_conn",
    "connect",
    "events_db_path",
    "get_conn",
    "suspended",
]


def events_db_path() -> Path:
    return crosswatch_db_path()


def _apply_event_schema(conn: sqlite3.Connection) -> sqlite3.Connection:
    from .schema import apply_schema

    with SCHEMA_LOCK:
        apply_schema(conn)
    return conn


def connect(path: str | os.PathLike[str] | None = None) -> sqlite3.Connection:
    return _apply_event_schema(_connect(path))


def get_conn() -> sqlite3.Connection | None:
    conn = _get_conn()
    if conn is None:
        return None
    if getattr(_APPLIED, "conn", None) is conn:
        return conn
    try:
        _apply_event_schema(conn)
    except Exception:
        return None
    _APPLIED.conn = conn
    return conn
