# tests/test_publicmetadb_specials.py
# Regression tests: PublicMetaDB must preserve season 0 (specials) in progress
# and episode-rating rows. A truthiness check (`season or season_number`) drops
# a valid season 0, causing specials to be omitted from the sync index.
from __future__ import annotations

from providers.sync.publicmetadb._progress import _to_minimal as progress_to_minimal
from providers.sync.publicmetadb._ratings import _to_minimal as ratings_to_minimal


def test_progress_preserves_season_zero_special() -> None:
    row = {
        "media_type": "episode",
        "ids": {"tmdb": "123"},
        "season": 0,            # special; no separate season_number provided
        "episode": 2,
        "progress_ms": 5000,
    }
    out = progress_to_minimal(row)
    assert out is not None, "season 0 special was dropped from progress"
    assert out["season"] == 0
    assert out["episode"] == 2


def test_progress_still_handles_regular_season() -> None:
    row = {
        "media_type": "episode",
        "ids": {"tmdb": "123"},
        "season": 3,
        "episode": 2,
        "progress_ms": 5000,
    }
    out = progress_to_minimal(row)
    assert out is not None
    assert out["season"] == 3


def test_progress_falls_back_to_season_number_when_season_absent() -> None:
    row = {
        "media_type": "episode",
        "ids": {"tmdb": "123"},
        "season_number": 0,     # season key missing entirely -> use season_number
        "episode": 1,
        "progress_ms": 5000,
    }
    out = progress_to_minimal(row)
    assert out is not None
    assert out["season"] == 0


def test_ratings_preserves_season_zero_special() -> None:
    row = {
        "ids": {"tmdb": "123"},
        "season": 0,
        "episode": 2,
        "score": 8,
    }
    out = ratings_to_minimal(row, episode_rating=True)
    assert out is not None, "season 0 special was dropped from episode ratings"
    assert out["season"] == 0
    assert out["episode"] == 2


def test_ratings_still_handles_regular_season() -> None:
    row = {
        "ids": {"tmdb": "123"},
        "season": 1,
        "episode": 4,
        "score": 9,
    }
    out = ratings_to_minimal(row, episode_rating=True)
    assert out is not None
    assert out["season"] == 1
