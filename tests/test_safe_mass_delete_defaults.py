from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cw_platform.config_base import DEFAULT_CFG, apply_migration_overrides, load_config
from cw_platform.orchestrator._pairs_massdelete import maybe_block_mass_delete


def test_new_configs_enable_delete_guards_by_default(config_base: Path) -> None:
    sync_defaults = DEFAULT_CFG["sync"]

    assert sync_defaults["drop_guard"] is True
    assert sync_defaults["allow_mass_delete"] is False

    effective = load_config()["sync"]
    assert effective["drop_guard"] is True
    assert effective["allow_mass_delete"] is False


def test_load_config_preserves_explicit_delete_guard_opt_out(config_base: Path) -> None:
    (config_base / "config.json").write_text(
        json.dumps({"sync": {"drop_guard": False, "allow_mass_delete": True}}),
        encoding="utf-8",
    )

    effective = load_config()["sync"]

    assert effective["drop_guard"] is False
    assert effective["allow_mass_delete"] is True


def test_upgrade_migration_replaces_legacy_unsafe_defaults() -> None:
    migrated, paths = apply_migration_overrides(
        {"sync": {"drop_guard": False, "allow_mass_delete": True}}
    )

    assert migrated["sync"]["drop_guard"] is True
    assert migrated["sync"]["allow_mass_delete"] is False
    assert "sync.drop_guard" in paths
    assert "sync.allow_mass_delete" in paths


def test_effective_default_blocks_mass_delete_plan(config_base: Path) -> None:
    events: list[tuple[str, dict[str, Any]]] = []
    removals = [{"ids": {"imdb": f"tt{i:04d}"}} for i in range(11)]
    sync = load_config()["sync"]

    guarded = maybe_block_mass_delete(
        removals,
        baseline_size=100,
        allow_mass_delete=sync["allow_mass_delete"],
        suspect_ratio=0.10,
        emit=lambda event, **data: events.append((event, data)),
        dbg=lambda *_args, **_kwargs: None,
        dst_name="PLEX",
        feature="watchlist",
    )

    assert guarded == []
    assert events == [
        (
            "mass_delete:blocked",
            {
                "dst": "PLEX",
                "feature": "watchlist",
                "attempted": 11,
                "baseline": 100,
                "threshold": 10,
            },
        )
    ]
