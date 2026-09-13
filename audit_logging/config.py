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
from pydantic_settings import BaseSettings, EnvSettingsSource, SettingsConfigDict
from pydantic_settings.sources import PydanticBaseSettingsSource

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


#: Fields whose environment value we parse ourselves (CSV *or* JSON).
_RAW_LIST_FIELDS = frozenset({"exclude_paths", "extra_redact_keys", "extra_header_allowlist"})


class _RawListEnvSource(EnvSettingsSource):
    """Stop pydantic-settings JSON-decoding our list fields before validation.

    ``AUDIT_EXCLUDE_PATHS=/health,/metrics`` is the form people actually write,
    and the default env source calls ``json.loads`` on any field it considers
    complex — so that value raises ``SettingsError`` before a validator ever
    sees it.

    ``NoDecode`` does exactly this and is the obvious answer, but it only
    exists in pydantic-settings >= 2.7.0 (measured, by bisection). Depending on
    it made this package unimportable for anyone on an older pin — a poor trade
    for a library, since the consumer's stack is not ours to dictate.

    **The constructor arguments are load-bearing.** On pydantic-settings 2.0.0,
    ``EnvSettingsSource(settings_cls)`` does not pick up ``env_prefix`` from
    ``model_config``: the prefix resolves to ``""``, no ``AUDIT_*`` variable
    matches, and substituting this source silently disables the **entire**
    environment layer rather than just the list fields. That failure is worse
    than the ImportError it replaced — ``AUDIT_ENABLED=false`` would be
    accepted and ignored, so an operator's kill switch would not take effect
    and nothing would say so. Passing the config explicitly makes it correct
    from 2.0.0 onward.
    """

    def prepare_field_value(
        self, field_name: str, field: Any, value: Any, value_is_complex: bool
    ) -> Any:
        if field_name in _RAW_LIST_FIELDS:
            return value
        return super().prepare_field_value(field_name, field, value, value_is_complex)


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

    # --- where the documents land (FR-33) -----------------------------------
    #: Overrides the dataset derived from ``service_name``. This is the second
    #: half of the index name: ``logs-<dataset>-<namespace>``.
    #:
    #: **It must start with** ``apiaudit.`` — the shipped index template is
    #: ``index_patterns: ["logs-apiaudit.*-*"]``, so a dataset outside that
    #: prefix means the template does not apply, the data stream is created
    #: with a *dynamic* mapping, and only a reindex fixes it (D-11). The
    #: validator below refuses it rather than letting that happen quietly.
    dataset: str | None = None
    #: Overrides the namespace, which otherwise follows ``environment``. Use it
    #: when the audit namespace and the deployment environment are not the same
    #: thing (one cluster serving several tenants, say).
    namespace: str | None = None

    # --- built-in shipping (FR-35, optional) --------------------------------
    #: Set this and the package ships its own records — no Filebeat needed.
    #:
    #: It does NOT change how the request path works. Records still go to a
    #: local JSONL file first; a background task then tails that file and bulk
    #: posts it. The file remains the durable buffer, so an Elasticsearch
    #: outage still cannot reach the application (D-13's actual purpose).
    #: Requires the ``elasticsearch`` extra: ``pip install audit-me[elasticsearch]``.
    elasticsearch_url: str | None = None
    elasticsearch_username: str | None = None
    elasticsearch_password: str | None = None
    #: Base64 ``id:api_key``. Takes precedence over username/password.
    elasticsearch_api_key: str | None = None
    #: Set false only for a self-signed cluster you control.
    elasticsearch_verify_certs: bool = True
    #: Install the ILM policy and index template on start. Leave it on unless
    #: an operator manages the mapping out of band — the shipper refuses to
    #: send anything until the template exists, because the first document
    #: would otherwise create a data stream with a dynamic mapping (D-11).
    elasticsearch_setup: bool = True
    #: Days before ILM deletes an index, or **None to never delete**.
    #:
    #: ``AUDIT_RETENTION_DAYS=never`` (or ``0``, or empty) drops the delete
    #: phase from the policy entirely, which is what an audit trail under a
    #: retention obligation needs — deleting evidence on a timer is the one
    #: failure mode you cannot recover from. 90 days is a default for the
    #: common case, not a recommendation.
    retention_days: int | None = 90
    #: When a new index is started. ``"1d"`` daily, ``"7d"`` weekly, ``"30d"``
    #: monthly, or **None for size-only** rollover.
    #: Indices carry the date in their name either way, and ``@timestamp``
    #: range queries work at any granularity — this changes shard count and
    #: how coarsely ILM can act, not what you can search.
    rollover_max_age: str | None = "7d"
    #: The other trigger, whichever comes first. None to disable.
    rollover_max_size: str | None = "50gb"
    ship_interval_seconds: float = Field(default=2.0, gt=0)
    ship_batch_size: int = Field(default=500, gt=0)
    ship_timeout_seconds: float = Field(default=30.0, gt=0)

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
    exclude_paths: list[str] = Field(
        default_factory=lambda: list(DEFAULT_EXCLUDE_PATHS)
    )

    # --- redaction (additive only, FR-13) -----------------------------------
    extra_redact_keys: list[str] = Field(default_factory=list)
    extra_header_allowlist: list[str] = Field(default_factory=list)

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

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Same precedence as the default, with our env source substituted."""
        config = settings_cls.model_config
        return (
            init_settings,
            # Pass these explicitly — see _RawListEnvSource's docstring. On
            # 2.0.0 they are not inherited from model_config, and the failure
            # is silent.
            _RawListEnvSource(
                settings_cls,
                case_sensitive=config.get("case_sensitive", False),
                env_prefix=config.get("env_prefix", ""),
                env_nested_delimiter=config.get("env_nested_delimiter"),
            ),
            dotenv_settings,
            file_secret_settings,
        )

    @field_validator("retention_days", mode="before")
    @classmethod
    def _retention_never(cls, v: Any) -> Any:
        """Accept ``never`` / ``0`` / empty as "keep forever"."""
        if v is None:
            return None
        if isinstance(v, str):
            t = v.strip().lower()
            if t in ("", "never", "forever", "none", "0", "keep"):
                return None
            v = int(t)
        if int(v) <= 0:
            return None
        return int(v)

    @field_validator("rollover_max_age", "rollover_max_size", mode="before")
    @classmethod
    def _rollover_off(cls, v: Any) -> Any:
        """Empty or ``none`` disables that trigger, leaving the other one."""
        if isinstance(v, str) and v.strip().lower() in ("", "none", "off", "never"):
            return None
        return v

    @field_validator("dataset")
    @classmethod
    def _dataset_must_match_the_template(cls, v: str | None) -> str | None:
        """Refuse a dataset the shipped index template cannot match.

        ``infra/elasticsearch/template-apiaudit.json`` is
        ``index_patterns: ["logs-apiaudit.*-*"]``. A dataset outside that
        prefix produces an index the template does not match, so Elasticsearch
        creates it with a **dynamic mapping** — which keeps working, and keeps
        indexing, until the field count explodes, and is fixable only by a
        reindex (D-11). That failure is silent at every layer, so it is caught
        here instead.
        """
        if v is None:
            return v
        if not v.startswith("apiaudit."):
            raise ValueError(
                f"dataset must start with 'apiaudit.' (got {v!r}). The shipped index "
                "template matches logs-apiaudit.*-* only; anything else silently gets a "
                "dynamic mapping that only a reindex can fix. To use a different prefix, "
                "change index_patterns in infra/elasticsearch/template-apiaudit.json and "
                "reinstall the template first."
            )
        if len(v) <= len("apiaudit."):
            raise ValueError("dataset needs something after the 'apiaudit.' prefix")
        return v

    @model_validator(mode="after")
    def _rollover_needs_a_trigger(self) -> AuditConfig:
        """An index that never rolls over grows until it breaks.

        With both triggers off, one backing index takes every document
        forever — past Lucene's 2.1 billion document limit it simply refuses
        writes, and by then it is far too large to reindex comfortably.
        """
        if self.rollover_max_age is None and self.rollover_max_size is None:
            raise ValueError(
                "rollover_max_age and rollover_max_size cannot both be disabled: "
                "one backing index would grow without bound. Set a size "
                "(rollover_max_size='50gb') for size-only rollover."
            )
        return self

    @model_validator(mode="after")
    def _check_queue_bounds(self) -> AuditConfig:
        if self.queue_max_bytes < self.flush_max_bytes:
            raise ValueError(
                f"queue_max_bytes ({self.queue_max_bytes}) must be >= "
                f"flush_max_bytes ({self.flush_max_bytes})"
            )
        return self

    @staticmethod
    def _sanitise(value: str) -> str:
        """Lowercase, with anything outside ``[a-z0-9_.]`` replaced by ``_``.

        Elasticsearch rejects a data stream name containing ``\\ / * ? " < > | ,``
        a space, or an uppercase letter, so this is not cosmetic.
        """
        return "".join(
            ch if (ch.isascii() and (ch.isdigit() or ch.islower() or ch in "_.")) else "_"
            for ch in value.lower()
        )

    @property
    def data_stream_dataset(self) -> str:
        """``apiaudit.<sanitised service name>``, or the ``dataset`` override."""
        if self.dataset is not None:
            return self._sanitise(self.dataset)
        return f"apiaudit.{self._sanitise(self.service_name)}"

    @property
    def data_stream_namespace(self) -> str:
        """The ``namespace`` override, else ``environment`` (plan §6.2)."""
        return self._sanitise(self.namespace if self.namespace is not None else self.environment)

    @property
    def index_name(self) -> str:
        """The data stream these documents land in.

        Filebeat builds this from the three ``data_stream.*`` fields the
        package writes, so this is the whole routing contract in one string —
        useful for a startup log line, and for the query an operator runs when
        asking "where did my audit records go?".
        """
        return f"logs-{self.data_stream_dataset}-{self.data_stream_namespace}"
