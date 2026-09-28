"""§9 / round-2 #10: WARN once at startup when SIGTERM is not a Python handler."""

from __future__ import annotations

import logging
import signal
import threading
from typing import Any

import pytest

from audit_logging.semantic.startup import sigterm_hijacked, warn_if_sigterm_hijacked

LOG = logging.getLogger("audit_logging.test.startup")


@pytest.fixture(autouse=True)
def _restore_sigterm() -> Any:
    saved = signal.getsignal(signal.SIGTERM)
    yield
    signal.signal(signal.SIGTERM, saved)


def test_python_handler_is_not_hijacked(caplog: pytest.LogCaptureFixture) -> None:
    signal.signal(signal.SIGTERM, lambda *_: None)
    assert sigterm_hijacked() is False
    assert warn_if_sigterm_hijacked(LOG) is False
    assert caplog.records == []


def test_sig_dfl_is_hijacked_and_warns_once_with_the_hint(caplog: pytest.LogCaptureFixture) -> None:
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    assert sigterm_hijacked() is True
    with caplog.at_level(logging.WARNING):
        assert warn_if_sigterm_hijacked(LOG) is True
    [record] = caplog.records
    assert record.levelno == logging.WARNING
    assert "aspose" in record.getMessage() and "signal.signal(signal.SIGTERM" in record.getMessage()


def test_native_handler_none_is_hijacked(monkeypatch: pytest.MonkeyPatch) -> None:
    # getsignal returns None when the handler was installed from C.
    monkeypatch.setattr(signal, "getsignal", lambda _sig: None)
    assert sigterm_hijacked() is True


def test_sig_ign_is_hijacked() -> None:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    assert sigterm_hijacked() is True


def test_off_the_main_thread_is_false() -> None:
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    out: list[bool] = []
    t = threading.Thread(target=lambda: out.append(sigterm_hijacked()))
    t.start()
    t.join()
    assert out == [False]


def test_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_sig: int) -> Any:
        raise RuntimeError("x")

    monkeypatch.setattr(signal, "getsignal", boom)
    assert sigterm_hijacked() is False
    assert warn_if_sigterm_hijacked(LOG) is False

    class BadLogger:
        def warning(self, *a: Any) -> None:
            raise RuntimeError("log down")

    monkeypatch.undo()
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    assert warn_if_sigterm_hijacked(BadLogger()) is False  # type: ignore[arg-type]
