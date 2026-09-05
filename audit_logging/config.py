"""``AuditConfig`` — the one knob-bag for the package (plan §6.6).

Every field is readable from the environment with the ``AUDIT_`` prefix, so a
service can be tuned or switched off without a code change (FR-15).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

__all__ = ["AuditConfig", "DEFAULT_EXCLUDE_PATHS", "MAX_ALLOWED_BODY_BYTES"]

#: Hard ceiling on ``max_body_bytes`` regardless of configuration (D-4).
MAX_ALLOWED_BODY_BYTES = 16 * 1024 * 1024

DEFAULT_EXCLUDE_PATHS: list[str] = [
    "/health",
    "/healthz",
    "/ready",
    "/metrics",
    "/favicon.ico",
    "/docs",
    "/openapi.json",
]


class AuditConfig(BaseSettings):
    """Configuration for :class:`~audit_logging.middleware.AuditMiddleware`."""

    model_config = SettingsConfigDict(
        env_prefix="AUDIT_",
        extra="forbid",
        arbitrary_types_allowed=True,
    )

    # --- identity -----------------------------------------------------------
    service_name: str = Field(min_length=1)
    service_version: str = "unknown"
    environment: str = "dev"

    # --- kill switch (FR-15) ------------------------------------------------
    enabled: bool = True

    # --- file sink ----------------------------------------------------------
    log_dir: Path = Path("/var/log/audit")
    file_max_bytes: int = Field(default=256 * 1024 * 1024, gt=0)
    file_backup_count: int = Field(default=8, ge=0)
    fsync: bool = False

    # --- capture ------------------------------------------------------------
    max_body_bytes: int = Field(default=1_048_576, gt=0, le=MAX_ALLOWED_BODY_BYTES)
    #: Bound on the *shape* of a parsed body, not just its length. A 1 MiB
    #: body of ``[[],[],...]`` costs far more to parse and redact than a 1 MiB
    #: string; without this a client picks our CPU cost (review M-2).
    #: Past the cap the body is dropped as ``body_skipped="too_complex"`` --
    #: the audit *record* still exists, only its body is missing, and
    #: ``audit_bodies_skipped_total`` counts it.
    #:
    #: 10 000 is chosen to sit inside NFR-1's 5 ms budget, measured on a
    #: realistic order-batch payload::
    #:
    #:      6 802 nodes ( 76 KiB)   2.61 ms
    #:     17 002 nodes (191 KiB)   4.95 ms   <- budget
    #:     34 002 nodes (382 KiB)  10.14 ms
    #:     68 002 nodes (764 KiB)  19.90 ms
    #:
    #: A service with genuine bulk endpoints must raise this **and accept the
    #: latency**, or accept bodiless records for those routes. There is no
    #: setting that gives both.
    max_body_nodes: int = Field(default=10_000, gt=0)
    #: Bound on **distinct** key names in one client-supplied structure.
    #:
    #: ``max_body_nodes`` bounds nodes, which is the wrong axis for redaction
    #: cost: a repeated key is two dict lookups, a first-seen one costs
    #: ~1.4 us that no cache can amortise, and the client picks which it
    #: sends. Measured at the shipped node cap: 9,999 nodes of 4,999 distinct
    #: keys is **9.09 ms and accepted**, while 10,001 nodes of four repeated
    #: keys is 0.16 ms and refused (review N3-1). 2048 keeps the worst
    #: accepted body inside NFR-1 while leaving ordinary bulk payloads — which
    #: repeat their keys — untouched.
    max_distinct_keys: int = Field(default=2048, gt=0)
    #: Multipart part records are metadata only (D-5) but still unbounded in
    #: count without this (review S-4).
    max_multipart_parts: int = Field(default=256, gt=0)
    #: Bound on the query string, which is parsed, redacted and re-encoded on
    #: the request path exactly like a form body. Nothing bounded it until the
    #: verification review: a GET with **no body at all** and a 64 KB query
    #: cost 17.9 ms of event-loop stall, 3.6x the whole NFR-1 budget (N2-3).
    #: The pair bound is derived as ``max_query_bytes // 16`` so raising this
    #: raises both halves coherently. 8 KiB is what a default nginx or Apache
    #: will pass in a request line at all.
    max_query_bytes: int = Field(default=8192, gt=0)
    #: Bodies that are neither JSON nor form-encoded cannot be parsed, so the
    #: key-based denylist cannot be applied to them. Storing them anyway is how
    #: an unredacted secret reaches the index (review M-1), so the default is
    #: metadata-only. Turning this on enables a **best-effort** textual scrub
    #: that is weaker than the structured path — see docs/redaction.md.
    capture_text_bodies: bool = False
    #: Bound on the opt-in text scrub. The scrub is a regex pass, so it
    #: recreates M-2's event-loop stall on a large body (six passes over 1 MiB
    #: measured 56-122 ms). Past this many bytes the body is refused as
    #: ``too_complex`` rather than half-scrubbed. Only consulted when
    #: ``capture_text_bodies`` is on.
    max_scrub_bytes: int = Field(default=32 * 1024, gt=0)
    exclude_paths: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: list(DEFAULT_EXCLUDE_PATHS)
    )

    # --- redaction (additive only, FR-13) -----------------------------------
    extra_redact_keys: Annotated[list[str], NoDecode] = Field(default_factory=list)
    extra_header_allowlist: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # --- queue and flush ----------------------------------------------------
    queue_max_bytes: int = Field(default=64 * 1024 * 1024, gt=0)
    flush_max_bytes: int = Field(default=4 * 1024 * 1024, gt=0)
    flush_interval_seconds: float = Field(default=1.0, gt=0)
    shutdown_flush_timeout: float = Field(default=10.0, gt=0)

    # --- hooks --------------------------------------------------------------
    user_resolver: Callable[[dict[str, Any]], dict[str, Any] | None] | None = None

    @field_validator("exclude_paths", "extra_redact_keys", "extra_header_allowlist", mode="before")
    @classmethod
    def _split_csv(cls, v: Any) -> Any:
        """Accept ``AUDIT_EXCLUDE_PATHS=/a,/b`` as well as a JSON list."""
        if not isinstance(v, str):
            return v
        text = v.strip()
        if text.startswith("["):
            return json.loads(text)
        return [part.strip() for part in text.split(",") if part.strip()]

    @model_validator(mode="after")
    def _check_queue_bounds(self) -> AuditConfig:
        if self.queue_max_bytes < self.flush_max_bytes:
            raise ValueError(
                f"queue_max_bytes ({self.queue_max_bytes}) must be >= "
                f"flush_max_bytes ({self.flush_max_bytes})"
            )
        return self

    @property
    def data_stream_dataset(self) -> str:
        """``apiaudit.<sanitised service name>`` (plan §6.2)."""
        safe = "".join(
            ch if (ch.isascii() and (ch.isdigit() or ch.islower() or ch in "_.")) else "_"
            for ch in self.service_name.lower()
        )
        return f"apiaudit.{safe}"
