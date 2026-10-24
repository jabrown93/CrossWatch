# CrossWatch test scripts
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

os.environ.setdefault("CW_TRAKT_PACING", "0")


@pytest.fixture()
def config_base(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("CONFIG_BASE", str(tmp_path))
    from cw_platform import config_base as _cb

    monkeypatch.setattr(_cb, "CONFIG", tmp_path, raising=False)
    return tmp_path


@pytest.fixture(autouse=True)
def _reset_run_control():
    """Fork: cancel/queue-stop state is module-global; a test that requests a
    cancel would otherwise make whichever scheduler test runs next skip its jobs."""
    from cw_platform import run_control

    run_control.clear_cancel()
    run_control.clear_queue_stop()
    yield
    run_control.clear_cancel()
    run_control.clear_queue_stop()
