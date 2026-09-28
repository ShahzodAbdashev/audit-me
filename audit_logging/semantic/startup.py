"""Startup checks (§9, round-2 #10): warn when SIGTERM is not owned by Python.

Native runtimes (aspose via its .NET/JVM bridge, some gRPC/JVM embeddings) install
their own SIGTERM handler on import. Python then never runs the shutdown path, so
the file sink never flushes its last batch. Call :func:`warn_if_sigterm_hijacked`
once after the app has imported everything.
"""

from __future__ import annotations

import logging
import signal
import threading

__all__ = ["sigterm_hijacked", "warn_if_sigterm_hijacked"]

_HINT = (
    "SIGTERM is not handled by Python (handler: %r); a native runtime imported by the app "
    "(e.g. aspose) may own it, so audit records buffered at shutdown can be lost. Fix: after "
    "importing native runtimes, restore a Python handler, e.g. "
    "signal.signal(signal.SIGTERM, lambda *_: sys.exit(0)), or let uvicorn install its own."
)


def sigterm_hijacked() -> bool:
    """True when, in the main thread, SIGTERM is SIG_DFL or not a Python callable
    (``None`` = installed from C). False off the main thread or on any error."""
    try:
        if threading.current_thread() is not threading.main_thread():
            return False
        handler = signal.getsignal(signal.SIGTERM)
        return handler is signal.SIG_DFL or not callable(handler)
    except Exception:
        return False


def warn_if_sigterm_hijacked(logger: logging.Logger) -> bool:
    """Log one WARNING with the fix hint when :func:`sigterm_hijacked`; returns it. Never raises."""
    try:
        if not sigterm_hijacked():
            return False
        logger.warning(_HINT, signal.getsignal(signal.SIGTERM))
        return True
    except Exception:
        return False
