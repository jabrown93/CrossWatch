"""Every config-bound form element must be lockable, or explicitly excused.

The lock is driven by data-cfg-path on the element itself. A field that ships
without one is silently unlockable: the server still discards an env-owned
edit, but the UI gives no sign of it.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXCLUSIONS_FILE = ROOT / "tests" / "data" / "env_lock_exclusions.txt"

SCANNED = [
    "ui_frontend.py",
    "assets/js/modals/tls/index.js",
    "assets/js/playback_progress.js",
    *sorted(p.relative_to(ROOT).as_posix() for p in (ROOT / "providers" / "auth").glob("_auth_*.py")),
]

ELEMENT = re.compile(r"<(?:input|select|textarea)\b[^>]*")
ELEMENT_ID = re.compile(r'id="([A-Za-z0-9_.:-]+)"')
NO_ID = "(no id)"


def _exclusions() -> set[str]:
    lines = EXCLUSIONS_FILE.read_text(encoding="utf-8").splitlines()
    return {s for s in (line.strip() for line in lines) if s and not s.startswith("#")}


def _unannotated(rel: str) -> set[str]:
    text = (ROOT / rel).read_text(encoding="utf-8")
    found: set[str] = set()
    for match in ELEMENT.finditer(text):
        tag = match.group(0)
        if "data-cfg-path" in tag:
            continue
        elem_id = ELEMENT_ID.search(tag)
        found.add(f"{rel}:{elem_id.group(1) if elem_id else NO_ID}")
    return found


@pytest.mark.parametrize("rel", SCANNED)
def test_every_form_element_is_annotated_or_excluded(rel: str) -> None:
    missing = _unannotated(rel) - _exclusions()
    assert not missing, (
        "add data-cfg-path to these, or list them in "
        f"{EXCLUSIONS_FILE.relative_to(ROOT)} with a reason: {sorted(missing)}"
    )


def test_exclusions_file_has_no_stale_entries() -> None:
    """A stale exclusion hides a field that later became config-bound."""
    live = set().union(*(_unannotated(rel) for rel in SCANNED))
    stale = _exclusions() - live
    assert not stale, f"exclusions no longer match any element: {sorted(stale)}"


def test_annotated_paths_are_dotted_config_paths() -> None:
    bad: list[str] = []
    for rel in SCANNED:
        text = (ROOT / rel).read_text(encoding="utf-8")
        for path in re.findall(r'data-cfg-path="([^"]*)"', text):
            if not path or not re.fullmatch(r"[a-z0-9_]+(\.[a-z0-9_]+)+", path):
                bad.append(f"{rel}: {path!r}")
    assert not bad, f"malformed data-cfg-path values: {bad}"


def test_instance_root_matches_its_path_prefix() -> None:
    """A mismatched root would resolve to a path no lock can ever match."""
    bad: list[str] = []
    for rel in SCANNED:
        text = (ROOT / rel).read_text(encoding="utf-8")
        for tag in ELEMENT.finditer(text):
            root = re.search(r'data-cfg-instance-root="([^"]*)"', tag.group(0))
            if not root:
                continue
            path = re.search(r'data-cfg-path="([^"]*)"', tag.group(0))
            if not path or not path.group(1).startswith(root.group(1) + "."):
                bad.append(f"{rel}: {tag.group(0)[:80]}")
    assert not bad, f"instance root does not prefix its path: {bad}"
