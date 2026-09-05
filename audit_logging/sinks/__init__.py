"""Sink implementations."""

from __future__ import annotations

from .file_sink import FileSink
from .null_sink import NullSink

__all__ = ["FileSink", "NullSink"]
