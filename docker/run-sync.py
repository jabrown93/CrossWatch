#!/usr/bin/env python3
"""Run all configured sync pairs using the Orchestrator.

The runtime image is shell-less, so this replaces the former run-sync.sh.
Invoke inside the container, e.g.:

    docker exec crosswatch python /app/docker/run-sync.py

Relies on the image's PYTHONPATH=/app and the venv on PATH. Exits non-zero
on failure and prints full output.
"""

from __future__ import annotations

import json
import sys
import traceback

from cw_platform.config_base import load_config
from cw_platform.orchestrator import Orchestrator


def coerce_bool(value, default=False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def main() -> int:
    try:
        cfg = load_config() or {}
        runtime_cfg = cfg.get("runtime") or {}
        sync_cfg = cfg.get("sync") or {}
        write_state_json = coerce_bool(
            sync_cfg.get("write_state_json", runtime_cfg.get("write_state_json", True)),
            True,
        )
        orc = Orchestrator(cfg)
        result = orc.run_pairs(write_state_json=write_state_json)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return int(result.get("exit_code", 0)) if isinstance(result, dict) else 0
    except Exception as e:  # noqa: BLE001
        print(f"[RUN] Sync failed: {e}", file=sys.stderr)
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
