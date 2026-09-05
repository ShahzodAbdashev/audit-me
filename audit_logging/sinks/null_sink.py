"""``NullSink`` — a :class:`~audit_logging._contracts.Sink` that only remembers.

Used by tests and by anyone who wants the middleware's capture behaviour
without a file on disk. It keeps every submitted document in ``submitted``,
so a test can assert on the document without going near Elasticsearch.
"""

from __future__ import annotations

from typing import Any

from .._contracts import Sink

__all__ = ["NullSink"]


class NullSink(Sink):
    """No-op sink that records what it was given.

    ``max_documents`` bounds the in-memory list so a long-running test cannot
    grow it without limit; older documents are discarded first.
    """

    def __init__(self, *, max_documents: int | None = None) -> None:
        self.submitted: list[dict[str, Any]] = []
        self.started = False
        self.closed = False
        self.flush_count = 0
        self._max_documents = max_documents

    async def start(self) -> None:
        self.started = True

    def submit(self, doc: dict[str, Any]) -> bool:
        self.submitted.append(doc)
        if self._max_documents is not None and len(self.submitted) > self._max_documents:
            del self.submitted[: len(self.submitted) - self._max_documents]
        return True

    async def flush(self) -> None:
        self.flush_count += 1

    async def close(self) -> None:
        self.closed = True

    # -- test conveniences ---------------------------------------------------

    def clear(self) -> None:
        self.submitted.clear()

    @property
    def only(self) -> dict[str, Any]:
        """The single submitted document, or an assertion failure."""
        if len(self.submitted) != 1:
            raise AssertionError(f"expected exactly 1 document, got {len(self.submitted)}")
        return self.submitted[0]
