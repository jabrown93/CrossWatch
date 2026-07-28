# CrossWatch test scripts
from __future__ import annotations

import pytest


@pytest.fixture()
def cw(config_base):
    import crosswatch

    return crosswatch


def test_reader_does_not_create_buffer_for_unknown_tag(cw) -> None:
    tag = "NOTAREALTAG"
    assert tag not in cw.LOG_BUFFERS

    assert cw._get_log_buf(tag, create=False) == []
    assert tag not in cw.LOG_BUFFERS
    assert tag not in cw.LOG_NEXT_SEQ
    assert tag not in cw.LOG_BASE_SEQ

    assert cw._log_lines(tag) == []
    assert tag not in cw.LOG_BUFFERS


def test_logs_dump_does_not_create_buffer(cw) -> None:
    tag = "ANOTHERFAKETAG"
    body = cw.logs_dump(channel=tag, n=10)
    assert body == {"channel": tag, "lines": []}
    assert tag not in cw.LOG_BUFFERS


def test_writer_still_creates_and_reader_sees_lines(cw) -> None:
    tag = "WRITERTAG"
    try:
        cw._append_log_to_buffer(tag, "hello")
        assert tag in cw.LOG_BUFFERS
        assert len(cw._get_log_buf(tag, create=False)) == 1
        assert len(cw._log_lines(tag)) == 1
    finally:
        cw.LOG_BUFFERS.pop(tag, None)
        cw.LOG_NEXT_SEQ.pop(tag, None)
        cw.LOG_BASE_SEQ.pop(tag, None)
