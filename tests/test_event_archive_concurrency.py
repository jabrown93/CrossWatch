"""Regression tests for the event archive's connection handling and hashing.

The archive is written from three places that run on different threads -- the
sync run, the webhook handlers and the scrobble watchers -- and every recorder
swallows write failures, so a concurrency bug here is invisible in the logs and
only shows up as missing history.
"""
from __future__ import annotations

import sqlite3
import threading

import pytest

from cw_platform.event_archive import db as ea_db
from cw_platform.event_archive import recorder as ea_recorder


@pytest.fixture
def archive(tmp_path, monkeypatch):
    path = tmp_path / "events.sqlite3"
    monkeypatch.setenv("CROSSWATCH_EVENTS_DB", str(path))
    ea_db.close_conn()
    yield path
    ea_db.close_conn()


def _row(**kwargs):
    base = {
        "event_type": "add",
        "item_key": "imdb:tt0111161",
        "source_provider": "PLEX",
        "destination_provider": "TRAKT",
        "feature": "watchlist",
        "operation": "add",
        "run_id": "run-1",
    }
    base.update(kwargs)
    return ea_recorder.make_event(**base)


def test_each_thread_gets_its_own_connection(archive):
    conns: list[sqlite3.Connection] = []
    barrier = threading.Barrier(4)

    def grab():
        barrier.wait()
        conns.append(ea_db.get_conn())

    threads = [threading.Thread(target=grab) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(conns) == 4
    assert all(c is not None for c in conns)
    assert len({id(c) for c in conns}) == 4


def test_same_thread_reuses_its_connection(archive):
    assert ea_db.get_conn() is ea_db.get_conn()


def test_concurrent_writers_lose_no_events(archive):
    """A shared connection interleaves implicit transactions and drops rows.

    Before per-thread connections this lost roughly half the events under this
    load, reporting only swallowed warnings.
    """
    threads_n, per_thread = 4, 60
    errors: list[str] = []
    start = threading.Barrier(threads_n)

    def write(worker: int):
        start.wait()
        for i in range(per_thread):
            try:
                written = ea_recorder.record_events(
                    [_row(item_key=f"imdb:tt{worker:02d}{i:04d}", run_id=f"run-{worker}")]
                )
                if written != 1:
                    errors.append(f"worker {worker} item {i} wrote {written}")
            except Exception as exc:  # pragma: no cover - failure detail only
                errors.append(f"{type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=write, args=(n,)) for n in range(threads_n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    count = ea_db.get_conn().execute("SELECT count(*) FROM events").fetchone()[0]
    assert count == threads_n * per_thread


def test_close_conn_drops_other_threads_connections(archive):
    """rebuild() unlinks the database right after close_conn().

    A handle left open elsewhere would keep writing into the unlinked inode.
    """
    holder: dict[str, sqlite3.Connection] = {}
    opened = threading.Event()
    release = threading.Event()

    def worker():
        holder["conn"] = ea_db.get_conn()
        opened.set()
        release.wait(timeout=5)
        holder["after"] = ea_db.get_conn()

    t = threading.Thread(target=worker)
    t.start()
    assert opened.wait(timeout=5)

    ea_db.close_conn()
    with pytest.raises(sqlite3.ProgrammingError):
        holder["conn"].execute("SELECT 1")

    release.set()
    t.join(timeout=5)
    assert holder["after"] is not None
    assert holder["after"] is not holder["conn"]


def test_writers_survive_concurrent_close_conn(archive):
    """maintenance rebuild() calls close_conn() while watchers keep recording.

    Writers must reconnect rather than reuse a closed handle, and no thread may
    end up registered against a connection opened before the invalidation.
    """
    written: list[int] = []
    attempts = 200
    stop = threading.Event()

    def write(worker: int):
        for i in range(attempts):
            if stop.is_set():
                break
            # record_events swallows write failures, so count its return value
            # rather than watching for exceptions that never escape.
            written.append(ea_recorder.record_events([_row(item_key=f"imdb:tt{worker}{i:05d}")]))

    threads = [threading.Thread(target=write, args=(n,)) for n in range(3)]
    for t in threads:
        t.start()
    for _ in range(20):
        ea_db.close_conn()
    for t in threads:
        t.join(timeout=10)
    stop.set()

    # A write racing an invalidation may legitimately return 0; a thread stuck on
    # a closed handle would return 0 forever.
    assert sum(written) > 0
    conn = ea_db.get_conn()
    assert conn is not None
    assert conn.execute("SELECT count(*) FROM events").fetchone()[0] == sum(written)


def test_no_connection_survives_the_rebuild_unlink(archive):
    """A connection opened mid-rebuild must not outlive the unlink.

    close_conn() alone left a window: a thread connecting after it returned but
    before the files were removed held the current generation, so nothing marked
    it stale once rebuild recreated the file, and its writes went to the
    deleted inode.
    """
    from cw_platform.event_archive import maintenance

    escaped: dict[str, object] = {}

    real_unlink = ea_db.Path.unlink

    def unlink_racing_a_writer(self, *args, **kwargs):
        # Stand in for a watcher thread that wakes up mid-rebuild.
        def racer():
            escaped["conn"] = ea_db.get_conn()

        t = threading.Thread(target=racer)
        t.start()
        t.join(timeout=5)
        return real_unlink(self, *args, **kwargs)

    ea_recorder.record_events([_row()])
    ea_db.Path.unlink = unlink_racing_a_writer
    try:
        result = maintenance.rebuild(reimport=False)
    finally:
        ea_db.Path.unlink = real_unlink

    assert result["ok"] is True
    # The racing thread is barred while the files are being replaced.
    assert escaped["conn"] is None

    # Post-rebuild writes land in the database the rebuild created.
    assert ea_recorder.record_events([_row(item_key="imdb:tt9999999")]) == 1
    fresh = sqlite3.connect(str(archive))
    try:
        rows = fresh.execute("SELECT item_key FROM events").fetchall()
    finally:
        fresh.close()
    assert [r[0] for r in rows] == ["imdb:tt9999999"]


def test_suspension_lifts_after_rebuild(archive):
    from cw_platform.event_archive import maintenance

    maintenance.rebuild(reimport=False)
    assert ea_db.get_conn() is not None


def test_suspension_lifts_when_rebuild_fails(archive):
    """rebuild() returns early on unlink failure; suspension must not stick."""
    from cw_platform.event_archive import maintenance

    real_unlink = ea_db.Path.unlink

    def boom(self, *args, **kwargs):
        raise OSError("nope")

    ea_recorder.record_events([_row()])
    ea_db.Path.unlink = boom
    try:
        result = maintenance.rebuild(reimport=False)
    finally:
        ea_db.Path.unlink = real_unlink

    assert result["ok"] is False
    assert ea_db.get_conn() is not None


def test_dead_threads_do_not_leak_connections(archive):
    for _ in range(5):
        t = threading.Thread(target=ea_db.get_conn)
        t.start()
        t.join()

    ea_db.get_conn()  # registration prunes entries for threads that exited
    assert len(ea_db._CONNS) == 1


def test_hash_separates_destination_instances():
    a = _row(destination_instance="default")
    b = _row(destination_instance="family")
    assert a["event_hash"] != b["event_hash"]


def test_hash_separates_source_and_origin_instances():
    assert _row(source_instance="a")["event_hash"] != _row(source_instance="b")["event_hash"]
    assert _row(origin_instance="a")["event_hash"] != _row(origin_instance="b")["event_hash"]


def test_hash_preserves_instance_case():
    """normalize_instance_id() only folds case for the default instance.

    get_provider_block() looks instances up by exact key, so "Family" and
    "family" can select different configured accounts and must not collide.
    """
    assert (
        _row(destination_instance="Family")["event_hash"]
        != _row(destination_instance="family")["event_hash"]
    )


@pytest.mark.parametrize("spelling", [None, "", "  ", "default", "DEFAULT"])
def test_default_instance_spellings_hash_alike(spelling):
    """Producers disagree on how they spell the default instance.

    Treating them as distinct would split single-instance installs into
    duplicate rows instead of deduplicating them.
    """
    assert _row(destination_instance=spelling)["event_hash"] == _row()["event_hash"]


def test_multi_instance_fanout_records_both(archive):
    rows = [
        _row(destination_instance="default"),
        _row(destination_instance="family"),
    ]
    assert ea_recorder.record_events(rows) == 2
    stored = ea_db.get_conn().execute(
        "SELECT destination_instance FROM events ORDER BY destination_instance"
    ).fetchall()
    assert [r[0] for r in stored] == ["default", "family"]
