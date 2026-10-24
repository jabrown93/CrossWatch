from __future__ import annotations

import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from cw_platform.local_db import db


@pytest.fixture()
def database(tmp_path, monkeypatch):
    monkeypatch.setenv("CROSSWATCH_DB", str(tmp_path / "crosswatch.sqlite3"))
    monkeypatch.setenv("CONFIG_BASE", str(tmp_path))
    db.close_conn()
    conn = db.get_conn()
    assert conn is not None
    with conn:
        conn.execute("CREATE TABLE concurrency_test (value TEXT)")
    yield conn
    db.close_conn()


def test_workers_cannot_read_or_commit_each_others_transaction(database):
    written = threading.Event()
    release = threading.Event()

    def writer():
        conn = db.get_conn()
        assert conn is not None
        try:
            with conn:
                conn.execute("INSERT INTO concurrency_test VALUES ('uncommitted')")
                written.set()
                assert release.wait(10)
                raise ValueError("roll back this worker")
        except ValueError:
            pass

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(writer)
        try:
            assert written.wait(10)
            assert database.execute("SELECT COUNT(*) FROM concurrency_test").fetchone()[0] == 0
            # A reader's commit must not commit the writer's pending insert.
            database.commit()
        finally:
            release.set()
        future.result(timeout=10)
    assert database.execute("SELECT COUNT(*) FROM concurrency_test").fetchone()[0] == 0


def test_connection_cache_and_close_cover_all_workers(database):
    barrier = threading.Barrier(3)

    def worker():
        conn = db.get_conn()
        assert conn is db.get_conn()
        barrier.wait(timeout=10)
        return conn

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(worker) for _ in range(2)]
        barrier.wait(timeout=10)
        connections = [database, *(future.result(timeout=10) for future in futures)]
        assert len({id(conn) for conn in connections}) == 3
        db.close_conn()
        for conn in connections:
            with pytest.raises(sqlite3.ProgrammingError, match="closed"):
                conn.execute("SELECT 1")
        replacement = db.get_conn()
        assert replacement is not database
        assert replacement.execute("SELECT COUNT(*) FROM concurrency_test").fetchone()[0] == 0


def test_finished_worker_connection_is_closed_on_next_lookup(database):
    with ThreadPoolExecutor(max_workers=1) as pool:
        conn = pool.submit(db.get_conn).result(timeout=10)
    assert db.get_conn() is database
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        conn.execute("SELECT 1")


def test_switching_database_replaces_only_current_workers_connection(database, tmp_path, monkeypatch):
    monkeypatch.setenv("CROSSWATCH_DB", str(tmp_path / "replacement.sqlite3"))
    replacement = db.get_conn()
    assert replacement is not None and replacement is not database
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        database.execute("SELECT 1")
    assert replacement.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_new_worker_connects_while_another_connection_holds_the_write_lock(database, tmp_path):
    holder = sqlite3.connect(str(tmp_path / "crosswatch.sqlite3"), isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            conn = pool.submit(db.get_conn).result(timeout=4)
        assert conn is not None
        assert conn.execute("SELECT COUNT(*) FROM concurrency_test").fetchone()[0] == 0
    finally:
        holder.rollback()
        holder.close()


def test_repeated_unavailable_warnings_are_rate_limited(database, monkeypatch, caplog):
    def fail(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(db, "connect", fail)
    monkeypatch.setattr(db, "_LAST_WARNING", {})
    monkeypatch.setattr(db, "_SUPPRESSED", {})
    db.close_conn()
    with caplog.at_level("WARNING", logger="crosswatch.local_db"):
        for _ in range(5):
            assert db.get_conn() is None
    assert [r.getMessage() for r in caplog.records].count("local database unavailable: database is locked") == 1
    monkeypatch.setattr(db, "_LAST_WARNING", {key: 0.0 for key in db._LAST_WARNING})
    caplog.clear()
    with caplog.at_level("WARNING", logger="crosswatch.local_db"):
        assert db.get_conn() is None
    assert any("4 similar warnings suppressed" in r.getMessage() for r in caplog.records)


def test_connect_overlapping_a_whole_suspension_is_not_cached(database, tmp_path, monkeypatch):
    path = tmp_path / "crosswatch.sqlite3"
    replacement = tmp_path / "replacement.sqlite3"
    seed = sqlite3.connect(replacement)
    seed.execute("CREATE TABLE concurrency_test (value TEXT)")
    seed.execute("INSERT INTO concurrency_test VALUES ('restored')")
    seed.commit()
    seed.close()
    real_connect = db.connect
    calls = []

    def connect_then_restore(*args, **kwargs):
        conn = real_connect(*args, **kwargs)
        if not calls:
            # A restore finishes its whole suspended() block before this worker
            # registers the handle it opened on the old inode.
            with db.suspended():
                for suffix in ("-wal", "-shm"):
                    path.with_name(path.name + suffix).unlink(missing_ok=True)
                replacement.replace(path)
        calls.append(conn)
        return conn

    def worker():
        monkeypatch.setattr(db, "connect", connect_then_restore)
        conn = db.get_conn()
        assert conn is not None
        return conn.execute("SELECT value FROM concurrency_test").fetchall()

    with ThreadPoolExecutor(max_workers=1) as pool:
        rows = pool.submit(worker).result(timeout=10)
    assert [tuple(r) for r in rows] == [("restored",)]
    assert len(calls) == 2
