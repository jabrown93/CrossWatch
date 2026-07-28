# CrossWatch test scripts
from __future__ import annotations

from api import syncAPI


def test_parse_resume_cursor_accepts_current_generation() -> None:
    assert syncAPI._parse_resume_cursor(f"{syncAPI._STREAM_GEN}:42") == 42


def test_parse_resume_cursor_rejects_foreign_or_malformed() -> None:
    assert syncAPI._parse_resume_cursor("deadbeef0000:42") == 0
    assert syncAPI._parse_resume_cursor("42") == 0
    assert syncAPI._parse_resume_cursor("") == 0
    assert syncAPI._parse_resume_cursor(None) == 0
    assert syncAPI._parse_resume_cursor(f"{syncAPI._STREAM_GEN}:notanum") == 0
    assert syncAPI._parse_resume_cursor(f"{syncAPI._STREAM_GEN}:-5") == 0
