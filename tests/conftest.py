# CrossWatch test scripts
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture()
def config_base(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("CONFIG_BASE", str(tmp_path))
    # Update the CONFIG variable in the config_base module to use the temp path
    import cw_platform.config_base
    monkeypatch.setattr(cw_platform.config_base, "CONFIG", tmp_path)
    return tmp_path
