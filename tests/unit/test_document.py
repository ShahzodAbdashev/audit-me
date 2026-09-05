"""Unit tests for ``build_document`` (A2) against ``docs/schema.md`` §2.

``redact.py`` belongs to A3 and still raises ``NotImplementedError`` in Phase 1,
so ``document.redact`` / ``document.filter_headers`` are monkeypatched here
(AGENTS.md, Phase 0 addendum). The stubs are identity by default; the tests
that care about redaction wiring install a minimal real one.
"""

from __future__ import annotations

import json
import os
import re
import socket
import time
from collections.abc import Iterable
from typing import Any

import pytest

from audit_logging import document as document_module
from audit_logging._contracts import (
    OUTCOME_DISCONNECTED,
    OUTCOME_FAILURE,
    RequestContext,
)
from audit_logging.config import AuditConfig
from audit_logging.document import build_document

# ---------------------------------------------------------------------------
# A3 stand-ins
# ---------------------------------------------------------------------------


def _identity_redact(
    obj: Any,
    keys: frozenset[str],
    *,
    depth_limit: int = 20,
    max_distinct_keys: int | None = None,
) -> Any:
    return obj


def _real_enough_redact(
    obj: Any,
    keys: frozenset[str],
    *,
    depth_limit: int = 20,
    max_distinct_keys: int | None = None,
) -> Any:
    """Just enough of FR-11 to prove the wiring, without touching redact.py."""
    if depth_limit <= 0:
        return "[TRUNCATED]"
    if isinstance(obj, dict):
        return {
            k: (
                "[REDACTED]"
                if _normalize_key(str(k)) in keys
                else _real_enough_redact(v, keys, depth_limit=depth_limit - 1)
            )
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_real_enough_redact(v, keys, depth_limit=depth_limit - 1) for v in obj]
    return obj


def _identity_filter_headers(
    headers: Iterable[tuple[bytes, bytes]], allowlist: frozenset[str]
) -> dict[str, str]:
    return {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in headers}


def _allowlist_filter_headers(
    headers: Iterable[tuple[bytes, bytes]], allowlist: frozenset[str]
) -> dict[str, str]:
    return {
        k.decode("latin-1").lower(): v.decode("latin-1")
        for k, v in headers
        if k.decode("latin-1").lower() in allowlist
    }


def _normalize_key(key: str) -> str:
    return key.lower().replace("_", "").replace("-", "").replace(".", "")


@pytest.fixture(autouse=True)
def _identity_redaction(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(document_module, "redact", _identity_redact)
    monkeypatch.setattr(document_module, "filter_headers", _identity_filter_headers)
    monkeypatch.setattr(document_module, "normalize_key", _normalize_key)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


class Route:
    def __init__(self, path: str) -> None:
        self.path = path


def make_config(**overrides: Any) -> AuditConfig:
    values: dict[str, Any] = {
        "service_name": "Orders-API",
        "service_version": "1.4.2",
        "environment": "prod",
    }
    values.update(overrides)
    return AuditConfig(**values)


def make_ctx(**overrides: Any) -> RequestContext:
    scope: dict[str, Any] = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "path": "/orders/42/items",
        "query_string": b"",
        "headers": [
            (b"host", b"orders.test"),
            (b"content-type", b"application/json"),
            (b"user-agent", b"python-httpx/0.28.1"),
            (b"content-length", b"812"),
        ],
        "client": ("10.42.0.31", 51234),
        "route": Route("/orders/{order_id}/items"),
        "path_params": {"order_id": 42},
    }
    scope.update(overrides.pop("scope", {}))
    started = time.monotonic_ns()
    fields: dict[str, Any] = {
        "trace_id": "9f2c1a7d4e8b4f0aa1c3d5e7f9b0c2d4",
        "started_ns": started,
        "ended_ns": started + 4_211_000,
        "scope": scope,
        "method": "POST",
        "raw_path": "/orders/42/items",
        "query_string": b"",
        "content_type": "application/json",
        "body": b"",
        "body_skipped": "empty",
        "status_code": 201,
        "response_headers": [(b"content-type", b"application/json")],
        "response_bytes": 128,
    }
    fields.update(overrides)
    return RequestContext(**fields)


# ===========================================================================
# Envelope, event, identity (schema §2.1 – §2.3)
# ===========================================================================


def test_envelope_matches_the_schema() -> None:
    doc = build_document(make_ctx(), make_config())
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", doc["@timestamp"])
    assert doc["data_stream"] == {
        "type": "logs",
        "dataset": "apiaudit.orders_api",
        "namespace": "prod",
    }


def test_event_block_is_constant_apart_from_duration_and_outcome() -> None:
    doc = build_document(make_ctx(), make_config())
    assert doc["event"] == {
        "kind": "event",
        "category": ["web"],
        "type": ["access"],
        "action": "http-request",
        "duration": 4_211_000,
        "outcome": "success",
    }


def test_identity_and_origin_blocks() -> None:
    doc = build_document(make_ctx(), make_config())
    assert doc["trace"] == {"id": "9f2c1a7d4e8b4f0aa1c3d5e7f9b0c2d4"}
    assert doc["service"] == {
        "name": "Orders-API",
        "version": "1.4.2",
        "environment": "prod",
    }
    assert doc["host"] == {"hostname": socket.gethostname()}
    assert doc["process"] == {"pid": os.getpid()}
    assert doc["client"] == {"ip": "10.42.0.31", "port": 51234}
    assert doc["user_agent"] == {"original": "python-httpx/0.28.1"}


def test_client_block_absent_when_the_scope_has_no_client() -> None:
    doc = build_document(make_ctx(scope={"client": None}), make_config())
    assert "client" not in doc


def test_document_is_json_serialisable() -> None:
    doc = build_document(make_ctx(), make_config())
    assert json.loads(json.dumps(doc))["trace"]["id"] == doc["trace"]["id"]


def test_no_unexpected_top_level_keys() -> None:
    """The index template is ``dynamic: false`` — nothing may leak in."""
    doc = build_document(
        make_ctx(user={"id": "u-1"}, exc=ValueError("x"), outcome=OUTCOME_FAILURE),
        make_config(),
    )
    assert set(doc) == {
        "@timestamp",
        "data_stream",
        "event",
        "trace",
        "service",
        "host",
        "process",
        "url",
        "http",
        "client",
        "user_agent",
        "user",
        "error",
        "audit",
    }


# ===========================================================================
# HTTP / URL (schema §2.4)
# ===========================================================================


def test_http_block() -> None:
    doc = build_document(make_ctx(), make_config())
    assert doc["http"]["version"] == "1.1"
    assert doc["http"]["request"]["method"] == "POST"
    assert doc["http"]["request"]["mime_type"] == "application/json"
    assert doc["http"]["request"]["bytes"] == 812  # declared Content-Length
    assert doc["http"]["response"] == {"status_code": 201, "bytes": 128}


def test_mime_type_drops_parameters() -> None:
    ctx = make_ctx(content_type="application/json; charset=utf-8")
    assert build_document(ctx, make_config())["http"]["request"]["mime_type"] == (
        "application/json"
    )


def test_request_bytes_falls_back_to_the_captured_length() -> None:
    ctx = make_ctx(
        body=b'{"a":1}',
        body_skipped=None,
        scope={"headers": [(b"content-type", b"application/json")]},
    )
    assert build_document(ctx, make_config())["http"]["request"]["bytes"] == 7


def test_status_code_absent_when_no_response_started() -> None:
    ctx = make_ctx(status_code=None, outcome=OUTCOME_DISCONNECTED)
    doc = build_document(ctx, make_config())
    assert "status_code" not in doc["http"]["response"]
    assert doc["event"]["outcome"] == "disconnected"


# ===========================================================================
# FR-14 — query redaction
# ===========================================================================


def test_FR_14_query_is_parsed_and_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(document_module, "redact", _real_enough_redact)
    monkeypatch.setattr(document_module, "DEFAULT_REDACT_KEYS", frozenset({"token"}))
    ctx = make_ctx(query_string=b"expand=lines&token=abc123")
    doc = build_document(ctx, make_config())
    assert doc["audit"]["request"]["query"] == {"expand": "lines", "token": "[REDACTED]"}
    assert doc["url"]["query"] == "expand=lines&token=%5BREDACTED%5D"
    assert "abc123" not in json.dumps(doc)


def test_FR_13_extra_redact_keys_are_additive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(document_module, "redact", _real_enough_redact)
    monkeypatch.setattr(document_module, "DEFAULT_REDACT_KEYS", frozenset({"token"}))
    config = make_config(extra_redact_keys=["Tenant-Key"])
    ctx = make_ctx(query_string=b"tenant_key=t1&token=t2&keep=yes")
    doc = build_document(ctx, config)
    assert doc["audit"]["request"]["query"] == {
        "tenant_key": "[REDACTED]",
        "token": "[REDACTED]",
        "keep": "yes",
    }


def test_query_string_is_left_verbatim_when_nothing_is_redacted() -> None:
    ctx = make_ctx(query_string=b"a=1&b=hello+world&c")
    doc = build_document(ctx, make_config())
    assert doc["url"]["query"] == "a=1&b=hello+world&c"
    assert doc["audit"]["request"]["query"] == {"a": "1", "b": "hello world", "c": ""}


def test_repeated_query_keys_become_a_list() -> None:
    doc = build_document(make_ctx(query_string=b"tag=a&tag=b"), make_config())
    assert doc["audit"]["request"]["query"] == {"tag": ["a", "b"]}


def test_empty_query_string() -> None:
    doc = build_document(make_ctx(), make_config())
    assert doc["url"]["query"] == ""
    assert doc["audit"]["request"]["query"] == {}


# ===========================================================================
# FR-12 — headers by allowlist
# ===========================================================================


def test_FR_12_headers_use_the_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(document_module, "filter_headers", _allowlist_filter_headers)
    monkeypatch.setattr(
        document_module, "DEFAULT_HEADER_ALLOWLIST", frozenset({"content-type"})
    )
    ctx = make_ctx(
        scope={
            "headers": [
                (b"content-type", b"application/json"),
                (b"authorization", b"Bearer hunter2"),
            ]
        }
    )
    doc = build_document(ctx, make_config())
    assert doc["audit"]["request"]["headers"] == {"content-type": "application/json"}
    assert "hunter2" not in json.dumps(doc)
    # user_agent.original only exists when the header survived the allowlist.
    assert "user_agent" not in doc


def test_FR_13_extra_header_allowlist_is_additive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(document_module, "filter_headers", _allowlist_filter_headers)
    monkeypatch.setattr(
        document_module, "DEFAULT_HEADER_ALLOWLIST", frozenset({"content-type"})
    )
    ctx = make_ctx(
        scope={
            "headers": [
                (b"content-type", b"application/json"),
                (b"x-tenant", b"acme"),
                (b"authorization", b"Bearer hunter2"),
            ]
        }
    )
    doc = build_document(ctx, make_config(extra_header_allowlist=["X-Tenant"]))
    assert doc["audit"]["request"]["headers"] == {
        "content-type": "application/json",
        "x-tenant": "acme",
    }


def test_response_headers_are_filtered_too() -> None:
    ctx = make_ctx(response_headers=[(b"content-type", b"application/json")])
    doc = build_document(ctx, make_config())
    assert doc["audit"]["response"]["headers"] == {"content-type": "application/json"}


# ===========================================================================
# FR-03 — route and path params
# ===========================================================================


def test_FR_03_route_and_stringified_path_params() -> None:
    doc = build_document(make_ctx(), make_config())
    assert doc["audit"]["route"] == "/orders/{order_id}/items"
    assert doc["audit"]["path_params"] == {"order_id": "42"}


def test_FR_03_unmatched_route() -> None:
    doc = build_document(
        make_ctx(scope={"route": None, "path_params": None}), make_config()
    )
    assert doc["audit"]["route"] == "unmatched"
    assert doc["audit"]["path_params"] == {}


def test_FR_03_route_with_path_format_only() -> None:
    class Legacy:
        path_format = "/legacy/{id}"

    doc = build_document(make_ctx(scope={"route": Legacy()}), make_config())
    assert doc["audit"]["route"] == "/legacy/{id}"


# ===========================================================================
# FR-09 / FR-07 / FR-08 — the body block
# ===========================================================================


def json_ctx(body: bytes, **overrides: Any) -> RequestContext:
    return make_ctx(
        body=body, body_skipped=None, content_type="application/json", **overrides
    )


def test_FR_09_object_body_is_parsed_into_body() -> None:
    doc = build_document(json_ctx(b'{"sku":"A-11","qty":3}'), make_config())
    request = doc["audit"]["request"]
    assert request["body"] == {"sku": "A-11", "qty": 3}
    # FR-30 / schema §2.9: parseable JSON emits ``body`` and nothing else.
    assert "body_raw" not in request
    assert request["body_parse_failed"] is False
    assert request["body_bytes"] == 22
    assert request["body_truncated"] is False
    assert "body_skipped" not in request


def test_FR_09_body_raw_holds_the_redacted_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-05: a secret must not survive anywhere in the document."""
    monkeypatch.setattr(document_module, "redact", _real_enough_redact)
    monkeypatch.setattr(document_module, "DEFAULT_REDACT_KEYS", frozenset({"password"}))
    doc = build_document(json_ctx(b'{"password":"hunter2"}'), make_config())
    assert doc["audit"]["request"]["body"] == {"password": "[REDACTED]"}
    assert "hunter2" not in json.dumps(doc)


@pytest.mark.parametrize("raw", [b"[1,2]", b'"x"', b"null", b"7", b"true"])
def test_FR_09_non_object_top_level_is_wrapped(raw: bytes) -> None:
    doc = build_document(json_ctx(raw), make_config())
    request = doc["audit"]["request"]
    assert request["body"] == {"_value": json.loads(raw)}
    assert "body_raw" not in request  # FR-30


def test_FR_09_parse_failure_keeps_the_raw_text() -> None:
    doc = build_document(json_ctx(b"{not json"), make_config())
    request = doc["audit"]["request"]
    assert request["body_parse_failed"] is True
    assert request["body_raw"] == "{not json"
    assert "body" not in request


def test_FR_09_duplicate_keys_are_last_wins() -> None:
    doc = build_document(json_ctx(b'{"a":1,"a":2}'), make_config())
    assert doc["audit"]["request"]["body"] == {"a": 2}


def test_FR_09_invalid_utf8_is_replaced_not_raised() -> None:
    doc = build_document(json_ctx(b'{"a":"\xff\xfe"}'), make_config())
    # Undecodable bytes become U+FFFD rather than an exception in the hot path.
    assert doc["audit"]["request"]["body"] == {"a": "��"}


def test_form_urlencoded_body_is_parsed_like_a_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(document_module, "redact", _real_enough_redact)
    monkeypatch.setattr(document_module, "DEFAULT_REDACT_KEYS", frozenset({"password"}))
    ctx = make_ctx(
        body=b"user=ann&password=hunter2",
        body_skipped=None,
        content_type="application/x-www-form-urlencoded",
    )
    doc = build_document(ctx, make_config())
    assert doc["audit"]["request"]["body"] == {
        "user": "ann",
        "password": "[REDACTED]",
    }
    assert "hunter2" not in json.dumps(doc)


def test_FR_28_text_body_is_not_stored_by_default() -> None:
    ctx = make_ctx(body=b"hello there", body_skipped=None, content_type="text/plain")
    request = build_document(ctx, make_config())["audit"]["request"]
    assert request["body_skipped"] == "content_type"
    assert "body" not in request
    assert "body_raw" not in request
    assert "body_parse_failed" not in request


def test_FR_28_capture_text_bodies_opts_in_to_the_raw_text() -> None:
    ctx = make_ctx(body=b"hello there", body_skipped=None, content_type="text/plain")
    config = make_config(capture_text_bodies=True)
    request = build_document(ctx, config)["audit"]["request"]
    assert request["body_raw"] == "hello there"
    assert "body" not in request
    assert "body_skipped" not in request
    assert "body_parse_failed" not in request


@pytest.mark.parametrize("skipped", ["empty", "unread"])
def test_body_skipped_reasons_carry_no_body(skipped: str) -> None:
    request = build_document(make_ctx(body_skipped=skipped), make_config())["audit"][
        "request"
    ]
    assert request["body_skipped"] == skipped
    assert "body" not in request
    assert "body_raw" not in request
    assert "body_parse_failed" not in request


def test_FR_08_truncation_is_flagged() -> None:
    ctx = json_ctx(b'{"a":"bbbb', body_truncated=True)
    request = build_document(ctx, make_config())["audit"]["request"]
    assert request["body_truncated"] is True
    assert request["body_bytes"] == 10
    assert request["body_parse_failed"] is True


def test_FR_07_binary_content_type_never_stores_bytes() -> None:
    ctx = make_ctx(
        body=b"\x89PNG\r\n\x1a\nsecret-bytes",
        body_skipped="content_type",
        content_type="image/png",
    )
    request = build_document(ctx, make_config())["audit"]["request"]
    assert request["body_skipped"] == "content_type"
    assert "body" not in request
    assert "body_raw" not in request
    assert "multipart" not in request


def test_FR_07_multipart_metadata_only() -> None:
    boundary = "X-BOUND"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="note"\r\n'
        "\r\n"
        "hello\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="upload"; filename="a.bin"\r\n'
        "Content-Type: application/octet-stream\r\n"
        "\r\n"
        "SECRET-PAYLOAD\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    ctx = make_ctx(
        body=body,
        body_skipped="content_type",
        content_type=f"multipart/form-data; boundary={boundary}",
    )
    request = build_document(ctx, make_config())["audit"]["request"]
    assert request["body_skipped"] == "content_type"
    assert "SECRET-PAYLOAD" not in json.dumps(request)
    parts = request["multipart"]["parts"]
    assert request["multipart"]["part_count"] == 2
    assert parts[0] == {"size": len("hello"), "name": "note"}
    assert parts[1] == {
        "size": len("SECRET-PAYLOAD"),
        "name": "upload",
        "filename": "a.bin",
        "content_type": "application/octet-stream",
    }


def test_FR_07_multipart_truncated_is_flagged_incomplete() -> None:
    ctx = make_ctx(
        body=b"--B\r\nContent-Disposition: form-data; name=",
        body_skipped="content_type",
        body_truncated=True,
        content_type="multipart/form-data; boundary=B",
    )
    request = build_document(ctx, make_config())["audit"]["request"]
    assert request["multipart"]["complete"] is False


def test_FR_07_multipart_without_a_boundary_is_survivable() -> None:
    ctx = make_ctx(
        body=b"whatever", body_skipped="content_type", content_type="multipart/form-data"
    )
    request = build_document(ctx, make_config())["audit"]["request"]
    assert request["multipart"]["part_count"] == 0


# ===========================================================================
# FR-25 / errors (schema §2.5, §2.6)
# ===========================================================================


def test_FR_25_user_block_keeps_only_id_name_roles() -> None:
    ctx = make_ctx(user={"id": "u-8813", "name": "a.k", "roles": ["op"], "email": "x@y"})
    doc = build_document(ctx, make_config())
    assert doc["user"] == {"id": "u-8813", "name": "a.k", "roles": ["op"]}
    assert "x@y" not in json.dumps(doc)


@pytest.mark.parametrize("user", [None, {}, {"email": "only-unknown-keys"}])
def test_FR_25_user_block_absent_when_there_is_nothing_to_say(
    user: dict[str, Any] | None,
) -> None:
    assert "user" not in build_document(make_ctx(user=user), make_config())


def test_error_block_on_failure() -> None:
    ctx = make_ctx(
        status_code=500, outcome=OUTCOME_FAILURE, exc=ValueError("kaboom"), user=None
    )
    doc = build_document(ctx, make_config())
    assert doc["error"] == {"type": "ValueError", "message": "kaboom"}
    assert doc["event"]["outcome"] == "failure"


def test_error_message_is_truncated_to_1024_chars() -> None:
    ctx = make_ctx(status_code=500, outcome=OUTCOME_FAILURE, exc=ValueError("x" * 5000))
    assert len(build_document(ctx, make_config())["error"]["message"]) == 1024


def test_no_stack_trace_is_ever_stored() -> None:
    try:
        raise RuntimeError("boom")
    except RuntimeError as exc:
        ctx = make_ctx(status_code=500, outcome=OUTCOME_FAILURE, exc=exc)
    doc = build_document(ctx, make_config())
    assert set(doc["error"]) == {"type", "message"}
    assert "Traceback" not in json.dumps(doc)


def test_error_block_absent_on_success() -> None:
    assert "error" not in build_document(make_ctx(), make_config())


# ===========================================================================
# Misc
# ===========================================================================


def test_duration_is_zero_when_the_response_never_ended() -> None:
    doc = build_document(make_ctx(ended_ns=None), make_config())
    assert doc["event"]["duration"] == 0


def test_dataset_sanitises_the_service_name() -> None:
    doc = build_document(make_ctx(), make_config(service_name="Orders API v2!"))
    assert doc["data_stream"]["dataset"] == "apiaudit.orders_api_v2_"


@pytest.mark.parametrize(
    ("content_type", "kind"),
    [
        ("application/json", "json"),
        ("application/json; charset=utf-8", "json"),
        ("application/vnd.api+json", "json"),
        ("text/json", "json"),
        ("application/x-www-form-urlencoded", "form"),
        ("text/plain", "text"),
        ("text/csv;charset=utf-8", "text"),
        ("application/xml", "text"),
        (None, "text"),
        ("multipart/form-data; boundary=x", "binary"),
        ("application/octet-stream", "binary"),
        ("image/png", "binary"),
    ],
)
def test_body_kind_classification(content_type: str | None, kind: str) -> None:
    assert document_module.body_kind_for(content_type) == kind


# ===========================================================================
# Regressions for the adversarial review (REVIEW.md) and AC-18…AC-24
# ===========================================================================


@pytest.fixture
def real_enough(monkeypatch: pytest.MonkeyPatch) -> None:
    """A denylist big enough to prove the wiring, without touching redact.py."""
    monkeypatch.setattr(document_module, "redact", _real_enough_redact)
    monkeypatch.setattr(
        document_module,
        "DEFAULT_REDACT_KEYS",
        frozenset({"password", "apikey", "token", "secret"}),
    )


_LEAKY_BODY = b'{"password":"hunter2","api_key":"AKIA-SECRET"}'


# --- M-1 / FR-28 / AC-18 ---------------------------------------------------


@pytest.mark.parametrize(
    "content_type",
    ["text/plain", "text/xml", "application/xml", "application/graphql", "text/csv", None],
)
def test_M_1_text_bodies_are_not_stored_unredacted(
    content_type: str | None, real_enough: None
) -> None:
    """REVIEW M-1: `Content-Type: text/plain` used to defeat the whole denylist.

    ``body_kind_for(None)`` is ``text`` too, so a request with no content type
    at all took the same path.
    """
    headers = [(b"content-type", content_type.encode())] if content_type else []
    ctx = make_ctx(
        body=_LEAKY_BODY,
        body_skipped=None,
        content_type=content_type,
        scope={"headers": headers},
    )
    doc = build_document(ctx, make_config())
    request = doc["audit"]["request"]
    assert request["body_skipped"] == "content_type"
    assert "body" not in request and "body_raw" not in request
    assert "hunter2" not in json.dumps(doc)
    assert "AKIA-SECRET" not in json.dumps(doc)


def test_AC_18_no_content_type_at_all_is_skipped_not_stored(real_enough: None) -> None:
    ctx = make_ctx(
        body=b'{"password":"p"}',
        body_skipped=None,
        content_type=None,
        scope={"headers": []},
    )
    doc = build_document(ctx, make_config())
    request = doc["audit"]["request"]
    assert request["body_skipped"] == "content_type"
    assert "body" not in request and "body_raw" not in request
    assert '"p"' not in json.dumps(doc)


@pytest.mark.parametrize(
    ("body", "content_type", "leak"),
    [
        (b'{"password": "hunter2", "keep": "yes"}', "text/plain", "hunter2"),
        (b"user=ann&password=hunter2", "text/plain", "hunter2"),
        (b"password: hunter2\nkeep: yes\n", "text/plain", "hunter2"),
        (b"<Envelope><password>hunter2</password></Envelope>", "application/xml", "hunter2"),
        (b'{"api_key":"AKIA"}', "text/plain", "AKIA"),
        (b'mutation { login(password: "hunter2") }', "application/graphql", "hunter2"),
    ],
)
def test_M_1_capture_text_bodies_scrubs_the_four_known_shapes(
    body: bytes, content_type: str, leak: str, real_enough: None
) -> None:
    """FR-28's opt-in path: best effort, but it must catch the obvious shapes."""
    ctx = make_ctx(body=body, body_skipped=None, content_type=content_type)
    doc = build_document(ctx, make_config(capture_text_bodies=True))
    assert leak not in json.dumps(doc)
    assert "[REDACTED]" in doc["audit"]["request"]["body_raw"]


def test_FR_28_the_scrub_keeps_non_denylisted_values(real_enough: None) -> None:
    ctx = make_ctx(
        body=b'{"keep": "visible", "password": "gone"}',
        body_skipped=None,
        content_type="text/plain",
    )
    raw = build_document(ctx, make_config(capture_text_bodies=True))["audit"]["request"][
        "body_raw"
    ]
    assert "visible" in raw
    assert "gone" not in raw


def test_FR_28_the_scrub_is_documented_as_weaker_than_the_structured_path(
    real_enough: None,
) -> None:
    """A2 must not oversell it: a secret in prose or a CSV column survives.

    Pinned deliberately so the limitation is visible to whoever reads these
    tests, and so A7 has something concrete to document.
    """
    ctx = make_ctx(
        body=b"name,ssn\na.karimov,123-45-6789\n",
        body_skipped=None,
        content_type="text/csv",
    )
    raw = build_document(ctx, make_config(capture_text_bodies=True))["audit"]["request"][
        "body_raw"
    ]
    assert "123-45-6789" in raw, "positional CSV columns are NOT scrubbed"


# --- M-2 / FR-29 / AC-19 ---------------------------------------------------


def _one_mib_of(unit: bytes, cap: int) -> bytes:
    return (b"[" + (unit + b",") * (cap // (len(unit) + 1)))[: cap - 1].rstrip(b",") + b"]"


@pytest.mark.parametrize("unit", [b"{}", b'{"a":1}', b"0", b"[]"])
def test_M_2_a_one_mib_adversarial_body_is_abandoned_not_parsed(unit: bytes) -> None:
    """REVIEW M-2: these took 56–176 ms of event-loop time each."""
    config = make_config()
    body = _one_mib_of(unit, config.max_body_bytes)
    ctx = json_ctx(body)
    started = time.perf_counter()
    doc = build_document(ctx, config)
    elapsed_ms = (time.perf_counter() - started) * 1000
    request = doc["audit"]["request"]
    assert request["body_skipped"] == "too_complex"
    assert "body" not in request and "body_raw" not in request
    assert elapsed_ms < 5.0, f"NFR-1 budget is 5 ms, took {elapsed_ms:.1f} ms"


def test_AC_19_a_one_mib_body_of_empty_lists_is_too_complex_and_fast() -> None:
    config = make_config()
    ctx = json_ctx(_one_mib_of(b"[]", config.max_body_bytes))
    started = time.perf_counter()
    doc = build_document(ctx, config)
    elapsed_ms = (time.perf_counter() - started) * 1000
    assert doc["audit"]["request"]["body_skipped"] == "too_complex"
    assert elapsed_ms < 5.0


def test_FR_29_the_node_cap_is_configurable_and_a_small_body_still_parses() -> None:
    config = make_config(max_body_nodes=4)
    assert build_document(json_ctx(b'{"a":1}'), config)["audit"]["request"]["body"] == {
        "a": 1
    }
    request = build_document(json_ctx(b"[1,2,3,4,5]"), config)["audit"]["request"]
    assert request["body_skipped"] == "too_complex"


def test_FR_29_a_form_body_is_bounded_by_the_same_cap() -> None:
    body = b"&".join(b"k%d=v" % i for i in range(50))
    ctx = make_ctx(
        body=body, body_skipped=None, content_type="application/x-www-form-urlencoded"
    )
    request = build_document(ctx, make_config(max_body_nodes=10))["audit"]["request"]
    assert request["body_skipped"] == "too_complex"
    assert "body" not in request


def test_FR_29_the_node_scan_is_an_upper_bound_never_a_lower_one() -> None:
    """The cheap pre-scan may over-count; it must never under-count.

    Under-counting would let an attacker-shaped body through the cap, which is
    the whole point of FR-29.
    """

    def count(node: Any) -> int:
        if isinstance(node, dict):
            return 1 + sum(count(v) for v in node.values())
        if isinstance(node, list):
            return 1 + sum(count(v) for v in node)
        return 1

    for raw in (
        b"{}",
        b"[]",
        b"5",
        b'{"a":1,"b":[1,2,{"c":3}]}',
        b"[[],[[]],[[[]]]]",
        b'{"a":{"b":{"c":{"d":1}}}}',
        b'[{"a":1},{"a":1},{"a":1}]',
    ):
        real = count(json.loads(raw))
        # estimate >= real  <=>  estimate > real - 1
        assert document_module._exceeds_node_cap(
            raw, real - 1, document_module._JSON_STRUCTURE
        ), raw


def test_FR_29_the_early_exit_agrees_with_a_full_scan() -> None:
    """The windowed scan must not change the answer, only when it is reached."""
    raw = b"[" + b"[]," * 40_000 + b"[]]"
    full = 1 + raw.count(b",") + raw.count(b"{") + raw.count(b"[")
    for limit in (1, 10, full - 1, full, full + 1):
        assert document_module._exceeds_node_cap(
            raw, limit, document_module._JSON_STRUCTURE
        ) is (full > limit)


# --- M-5 / FR-31 / AC-21 ---------------------------------------------------


def test_M_5_a_dict_in_user_roles_is_dropped_not_written_to_a_keyword() -> None:
    """REVIEW M-5: ignore_malformed does not cover ``keyword``.

    Elasticsearch answers the bulk item with a ``mapper_parsing_exception`` and
    rejects the whole document, so a mistyped resolver return deletes the audit
    record entirely.
    """
    doc = build_document(make_ctx(user={"id": "u1", "roles": {"nested": "obj"}}), make_config())
    assert doc["user"] == {"id": "u1"}


def test_AC_21_user_values_are_coerced_to_the_schema_types() -> None:
    ctx = make_ctx(user={"id": 7, "roles": {"a": "b"}})
    doc = build_document(ctx, make_config())
    assert doc["user"]["id"] == "7"
    assert "roles" not in doc["user"]


@pytest.mark.parametrize(
    ("user", "expected"),
    [
        ({"id": 7}, {"id": "7"}),
        ({"id": 1.5}, {"id": "1.5"}),
        ({"name": ["a", "b"]}, None),
        ({"id": None}, None),
        ({"roles": "operator"}, {"roles": ["operator"]}),
        ({"roles": ["op", 3, None, {"x": 1}]}, {"roles": ["op", "3"]}),
        ({"roles": []}, None),
        ({"roles": ("a", "b")}, {"roles": ["a", "b"]}),
        ({"id": "u1", "name": {"bad": 1}}, {"id": "u1"}),
    ],
)
def test_FR_31_user_coercion_table(
    user: dict[str, Any], expected: dict[str, Any] | None
) -> None:
    doc = build_document(make_ctx(user=user), make_config())
    assert doc.get("user") == expected


def test_FR_31_user_strings_are_bounded() -> None:
    doc = build_document(make_ctx(user={"id": "u" * 9000}), make_config())
    assert len(doc["user"]["id"]) == 1024


def test_FR_31_roles_are_bounded_in_count() -> None:
    doc = build_document(make_ctx(user={"roles": [str(i) for i in range(500)]}), make_config())
    assert len(doc["user"]["roles"]) == 64


# --- FR-30 / AC-20 ---------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "content_type", "skipped", "capture_text"),
    [
        (b'{"a":1}', "application/json", None, False),
        (b"{not json", "application/json", None, False),
        (b"a=1", "application/x-www-form-urlencoded", None, False),
        (b"hello", "text/plain", None, False),
        (b"hello", "text/plain", None, True),
        (b"\x89PNG", "image/png", "content_type", False),
        (b"", "application/json", "empty", False),
        (b"", "application/json", "unread", False),
    ],
)
def test_FR_30_body_and_body_raw_are_mutually_exclusive(
    body: bytes, content_type: str, skipped: str | None, capture_text: bool
) -> None:
    ctx = make_ctx(body=body, body_skipped=skipped, content_type=content_type)
    request = build_document(ctx, make_config(capture_text_bodies=capture_text))["audit"][
        "request"
    ]
    assert not ("body" in request and "body_raw" in request)


def test_AC_20_a_one_mib_json_body_produces_one_copy_not_two() -> None:
    """M-3's root cause on A2's side: the line was double the body."""
    config = make_config()
    body = json.dumps({"pad": "z" * (config.max_body_bytes - 64)}).encode()
    doc = build_document(json_ctx(body), config)
    request = doc["audit"]["request"]
    assert "body_raw" not in request
    line = json.dumps(doc, separators=(",", ":"))
    # Filebeat's message_max_bytes is 2 MiB; one copy of a 1 MiB body fits.
    assert len(line.encode()) < 2_097_152


def test_FR_30_schema_2_9_table() -> None:
    """Each row of ``docs/schema.md`` §2.9, exactly."""
    config = make_config()
    rows: list[tuple[RequestContext, AuditConfig, str | None, bool | None, str | None]] = [
        (json_ctx(b'{"a":1}'), config, "body", False, None),
        (json_ctx(b"{oops"), config, "body_raw", True, None),
        (
            make_ctx(body=b"a=1", body_skipped=None, content_type=_FORM),
            config,
            "body",
            False,
            None,
        ),
        (
            make_ctx(body=b"hi", body_skipped=None, content_type="text/plain"),
            make_config(capture_text_bodies=True),
            "body_raw",
            None,
            None,
        ),
        (
            make_ctx(body=b"hi", body_skipped=None, content_type="text/plain"),
            config,
            None,
            None,
            "content_type",
        ),
        (
            make_ctx(body=b"x", body_skipped="content_type", content_type="image/png"),
            config,
            None,
            None,
            "content_type",
        ),
        (
            json_ctx(_one_mib_of(b"[]", config.max_body_bytes)),
            config,
            None,
            None,
            "too_complex",
        ),
        (make_ctx(body_skipped="empty"), config, None, None, "empty"),
        (make_ctx(body_skipped="unread"), config, None, None, "unread"),
    ]
    for ctx, cfg, emitted, parse_failed, skipped in rows:
        request = build_document(ctx, cfg)["audit"]["request"]
        for field in ("body", "body_raw"):
            assert (field in request) is (field == emitted), (field, request)
        assert request.get("body_parse_failed") is parse_failed
        assert request.get("body_skipped") == skipped


_FORM = "application/x-www-form-urlencoded"


# --- S-2 / N-1: the last unredacted path ----------------------------------


def test_S_2_a_deliberately_broken_json_body_is_the_only_unredacted_path(
    real_enough: None,
) -> None:
    """AC-14 demands the raw text; AC-05 demands no secret anywhere.

    They genuinely conflict here and AC-14 wins by construction — there is
    nothing parsed to re-dump. What A2 controls is how *much* it keeps.
    """
    doc = build_document(json_ctx(b'{"password":"hunter2", oops}'), make_config())
    request = doc["audit"]["request"]
    assert request["body_parse_failed"] is True
    assert request["body_raw"] == '{"password":"hunter2", oops}'


def test_S_2_the_unredacted_path_is_clipped() -> None:
    body = b'{"password":"' + b"h" * 20000 + b'", oops}'
    request = build_document(json_ctx(body), make_config())["audit"]["request"]
    assert len(request["body_raw"]) == 4096
    assert request["body_truncated"] is True


def test_N_1_a_disconnect_mid_json_keeps_only_the_prefix_it_received() -> None:
    request = build_document(json_ctx(b'{"a":'), make_config())["audit"]["request"]
    assert request["body_parse_failed"] is True
    assert request["body_raw"] == '{"a":'


# --- S-3: query separators -------------------------------------------------


def test_S_3_semicolon_separated_query_pairs_are_redacted(real_enough: None) -> None:
    """REVIEW S-3: ``;`` bypassed FR-14 in both ``url.query`` and ``audit``."""
    doc = build_document(make_ctx(query_string=b"a=1;token=SECRET"), make_config())
    assert doc["audit"]["request"]["query"] == {"a": "1", "token": "[REDACTED]"}
    assert "SECRET" not in json.dumps(doc)


def test_S_3_percent_encoded_whitespace_keys_are_redacted(real_enough: None) -> None:
    doc = build_document(make_ctx(query_string=b"%20token=SECRET"), make_config())
    assert doc["audit"]["request"]["query"] == {"token": "[REDACTED]"}
    assert "SECRET" not in json.dumps(doc)


def test_S_3_a_semicolon_separated_form_body_is_redacted(real_enough: None) -> None:
    ctx = make_ctx(
        body=b"user=a;password=hunter2", body_skipped=None, content_type=_FORM
    )
    doc = build_document(ctx, make_config())
    assert doc["audit"]["request"]["body"] == {"user": "a", "password": "[REDACTED]"}
    assert "hunter2" not in json.dumps(doc)


# --- S-4 / N-7: multipart --------------------------------------------------


def test_S_4_multipart_parts_are_capped() -> None:
    """REVIEW S-4: 1 MiB of tiny parts produced 104 857 records in 573 ms."""
    config = make_config()
    unit = b"--B\r\nz\r\n\r\n"
    body = unit * (config.max_body_bytes // len(unit))
    ctx = make_ctx(
        body=body,
        body_skipped="content_type",
        content_type="multipart/form-data; boundary=B",
    )
    started = time.perf_counter()
    multipart = build_document(ctx, config)["audit"]["request"]["multipart"]
    elapsed_ms = (time.perf_counter() - started) * 1000
    assert multipart["part_count"] == config.max_multipart_parts
    assert multipart["complete"] is False
    assert elapsed_ms < 5.0, f"took {elapsed_ms:.1f} ms"


def test_S_4_the_cap_is_configurable() -> None:
    body = b"".join(
        b'--B\r\nContent-Disposition: form-data; name="f%d"\r\n\r\nv\r\n' % i
        for i in range(20)
    ) + b"--B--\r\n"
    ctx = make_ctx(
        body=body,
        body_skipped="content_type",
        content_type="multipart/form-data; boundary=B",
    )
    multipart = build_document(ctx, make_config(max_multipart_parts=5))["audit"][
        "request"
    ]["multipart"]
    assert multipart["part_count"] == 5
    assert multipart["complete"] is False


def test_S_4_a_complete_multipart_under_the_cap_is_still_complete() -> None:
    body = (
        b'--B\r\nContent-Disposition: form-data; name="a"\r\n\r\nv\r\n'
        b'--B\r\nContent-Disposition: form-data; name="b"\r\n\r\nw\r\n'
        b"--B--\r\n"
    )
    ctx = make_ctx(
        body=body,
        body_skipped="content_type",
        content_type="multipart/form-data; boundary=B",
    )
    multipart = build_document(ctx, make_config())["audit"]["request"]["multipart"]
    assert multipart["part_count"] == 2
    assert multipart["complete"] is True


def test_N_7_a_filename_under_a_denylisted_part_name_is_redacted(
    real_enough: None,
) -> None:
    body = (
        b'--B\r\nContent-Disposition: form-data; name="password"; '
        b'filename="creds.txt"\r\n\r\nv\r\n--B--\r\n'
    )
    ctx = make_ctx(
        body=body,
        body_skipped="content_type",
        content_type="multipart/form-data; boundary=B",
    )
    parts = build_document(ctx, make_config())["audit"]["request"]["multipart"]["parts"]
    assert parts[0]["filename"] == "[REDACTED]"


def test_N_7_part_metadata_strings_are_bounded() -> None:
    body = (
        b'--B\r\nContent-Disposition: form-data; name="'
        + b"n" * 5000
        + b'"\r\n\r\nv\r\n--B--\r\n'
    )
    ctx = make_ctx(
        body=body,
        body_skipped="content_type",
        content_type="multipart/form-data; boundary=B",
    )
    parts = build_document(ctx, make_config())["audit"]["request"]["multipart"]["parts"]
    assert len(parts[0]["name"]) == 256


# --- S-5: the degraded document -------------------------------------------


def test_S_5_a_hostile_client_port_no_longer_costs_the_record() -> None:
    ctx = make_ctx(scope={"client": ("1.2.3.4", "notaport")})
    doc = build_document(ctx, make_config())
    assert doc["client"] == {"ip": "1.2.3.4", "port": 0}


def test_S_5_the_degraded_document_is_a_hole_marker_not_a_hole() -> None:
    ctx = make_ctx()
    doc = document_module.build_minimal_document(ctx, make_config(), RuntimeError("boom"))
    assert doc["trace"]["id"] == ctx.trace_id
    assert doc["url"]["path"] == ctx.raw_path
    assert doc["http"]["request"]["method"] == "POST"
    assert doc["http"]["response"]["status_code"] == 201
    assert doc["event"]["outcome"] == "success"
    assert doc["error"]["type"] == "RuntimeError"
    assert doc["error"]["message"].startswith("audit_logging: ")
    assert "request" not in doc["audit"]  # the hole is visible, not silent


# --- S-1: http.request.bytes ----------------------------------------------


def test_S_1_request_bytes_prefers_what_the_middleware_actually_counted() -> None:
    ctx = make_ctx(
        body=b"A" * 32,
        body_truncated=True,
        body_skipped=None,
        content_type="text/plain",
        scope={"headers": [], document_module.RECEIVED_BYTES_KEY: 60},
    )
    assert build_document(ctx, make_config())["http"]["request"]["bytes"] == 60


def test_S_1_without_a_counter_a_truncated_chunked_body_is_a_visible_lower_bound() -> None:
    """No Content-Length, no counter: the field is a floor, and says so.

    ``body_truncated`` is true and ``body_bytes`` equals ``http.request.bytes``,
    which is the "at least this many" marker. Only reachable when someone calls
    ``build_document`` with a context this middleware did not build.
    """
    ctx = make_ctx(
        body=b"A" * 32,
        body_truncated=True,
        body_skipped=None,
        content_type="text/plain",
        scope={"headers": []},
    )
    doc = build_document(ctx, make_config())
    assert doc["http"]["request"]["bytes"] == 32
    assert doc["audit"]["request"]["body_bytes"] == 32
    assert doc["audit"]["request"]["body_truncated"] is True


# --- AC-24 -----------------------------------------------------------------


def test_AC_24_extra_redact_keys_are_additive_across_query_and_body(
    real_enough: None,
) -> None:
    config = make_config(extra_redact_keys=["tenant_ref"])
    ctx = make_ctx(
        query_string=b"tenant_ref=X&token=T",
        body=b'{"tenant_ref": "Y", "password": "P"}',
        body_skipped=None,
        content_type="application/json",
    )
    doc = build_document(ctx, config)
    blob = json.dumps(doc)
    assert "X" not in doc["audit"]["request"]["query"].values()
    assert doc["audit"]["request"]["query"]["tenant_ref"] == "[REDACTED]"
    assert doc["audit"]["request"]["body"]["tenant_ref"] == "[REDACTED]"
    # ...and every default key still redacts: extension is additive (FR-13).
    assert doc["audit"]["request"]["query"]["token"] == "[REDACTED]"
    assert doc["audit"]["request"]["body"]["password"] == "[REDACTED]"
    assert '"Y"' not in blob and '"P"' not in blob and '"T"' not in blob


def test_FR_28_the_scrub_is_bounded_in_length(real_enough: None) -> None:
    """The opt-in scrub must not reintroduce M-2 behind a config flag.

    Six regex passes over a 1 MiB body cost 56–122 ms — the same event-loop
    stall, just requiring one config change instead of one header.
    """
    config = make_config(capture_text_bodies=True)
    body = b"the quick brown fox jumps " * 50_000
    ctx = make_ctx(body=body, body_skipped=None, content_type="text/plain")
    started = time.perf_counter()
    request = build_document(ctx, config)["audit"]["request"]
    elapsed_ms = (time.perf_counter() - started) * 1000
    assert request["body_skipped"] == "too_complex"
    assert "body_raw" not in request
    assert elapsed_ms < 5.0, f"took {elapsed_ms:.1f} ms"


def test_FR_28_the_scrub_is_bounded_in_rewrite_sites(real_enough: None) -> None:
    config = make_config(capture_text_bodies=True)
    ctx = make_ctx(
        body=b"password=secret&" * 4000, body_skipped=None, content_type="text/plain"
    )
    request = build_document(ctx, config)["audit"]["request"]
    assert request["body_skipped"] == "too_complex"
    assert "body_raw" not in request


@pytest.mark.parametrize(
    "unit",
    [
        b"the quick brown fox jumps ",
        b"password=secret&",
        b'"password":"secret",',
        b"<password>secret</password>",
        b"password: secret\n",
    ],
)
def test_FR_28_a_scrubbed_body_at_the_budget_stays_inside_NFR_1(
    unit: bytes, real_enough: None
) -> None:
    config = make_config(capture_text_bodies=True)
    body = unit * (32 * 1024 // len(unit))  # whole units: see the test below
    ctx = make_ctx(body=body, body_skipped=None, content_type="text/plain")
    build_document(ctx, config)
    started = time.perf_counter()
    request = build_document(ctx, config)["audit"]["request"]
    elapsed_ms = (time.perf_counter() - started) * 1000
    assert "secret" not in (request.get("body_raw") or "")
    assert elapsed_ms < 5.0, f"took {elapsed_ms:.1f} ms"


def test_FR_28_a_value_cut_by_truncation_is_not_scrubbed(real_enough: None) -> None:
    """Another documented weakness of the textual path, pinned deliberately.

    A body truncated at ``max_body_bytes`` mid-element leaves the tail without
    its closing delimiter, so the pattern cannot match it. The structured path
    has no equivalent — a truncated JSON body simply fails to parse and takes
    the ``body_parse_failed`` route. For A7's ``docs/redaction.md``.
    """
    ctx = make_ctx(
        body=b"<password>secret",
        body_skipped=None,
        body_truncated=True,
        content_type="application/xml",
    )
    raw = build_document(ctx, make_config(capture_text_bodies=True))["audit"]["request"][
        "body_raw"
    ]
    assert raw == "<password>secret", "an unterminated element is NOT scrubbed"


# ===========================================================================
# REVIEW-2 N2-3 — the query string is bounded like a body
# ===========================================================================


class CountingMetrics:
    """Records counters. Never raises (contract §6.7)."""

    def __init__(self) -> None:
        self.counters: dict[str, float] = {}

    def inc(self, name: str, value: int = 1) -> None:
        self.counters[name] = self.counters.get(name, 0) + value

    def set(self, name: str, value: float) -> None:
        self.counters[name] = value

    def __getitem__(self, name: str) -> float:
        return self.counters.get(name, 0)


def query_ctx(query: bytes) -> RequestContext:
    """A ``GET`` with a query string and no body at all — N2-3's shape."""
    return make_ctx(
        method="GET",
        query_string=query,
        content_type=None,
        body=b"",
        body_skipped="empty",
        scope={"method": "GET", "query_string": query},
    )


@pytest.mark.parametrize(
    ("name", "query"),
    [
        ("8 KB", b"a&" * 4096),
        ("16 KB", b"a&" * 8192),
        ("64 KB", b"a&" * 32768),
        ("164 KB, 20 000 distinct keys", b"&".join(b"k%05d=v%05d" % (i, i) for i in range(20000))),
    ],
)
def test_N2_3_a_large_query_string_is_refused_not_parsed(name: str, query: bytes) -> None:
    """REVIEW-2 N2-3: 8.3 ms at 8 KB and 24 ms at 64 KB, on a GET with no body.

    ``max_body_nodes`` bounded the body; the query string was parsed, redacted
    and re-encoded on the same request path with nothing bounding it at all.
    """
    config = make_config()
    started = time.perf_counter()
    doc = build_document(query_ctx(query), config)
    elapsed_ms = (time.perf_counter() - started) * 1000
    request = doc["audit"]["request"]
    assert request["query_skipped"] == "too_complex", name
    assert request["query"] == {}
    assert doc["url"]["query"] == document_module.QUERY_SKIPPED_MARKER
    assert elapsed_ms < 5.0, f"NFR-1 budget is 5 ms, {name} took {elapsed_ms:.2f} ms"


def test_N2_3_the_worst_query_the_bound_admits_is_well_inside_the_budget() -> None:
    """The bound is only worth what the largest thing it *accepts* costs."""
    config = make_config()
    query = b"&".join(b"k%03d=%s" % (i, b"v" * 10) for i in range(512))
    assert len(query) <= 8 * 1024
    started = time.perf_counter()
    request = build_document(query_ctx(query), config)["audit"]["request"]
    elapsed_ms = (time.perf_counter() - started) * 1000
    assert "query_skipped" not in request
    assert len(request["query"]) == 512
    assert elapsed_ms < 5.0, f"NFR-1 budget is 5 ms, took {elapsed_ms:.2f} ms"


def test_N2_3_an_ordinary_query_is_still_captured_and_redacted(
    real_enough: None,
) -> None:
    """The bound must not be a blanket refusal: normal queries still parse."""
    doc = build_document(query_ctx(b"expand=lines&token=SECRET&page=3"), make_config())
    request = doc["audit"]["request"]
    assert "query_skipped" not in request
    assert request["query"] == {"expand": "lines", "token": "[REDACTED]", "page": "3"}
    assert doc["url"]["query"] == "expand=lines&token=%5BREDACTED%5D&page=3"
    assert "SECRET" not in json.dumps(doc)


def test_N2_3_a_refused_query_is_not_a_redaction_bypass(real_enough: None) -> None:
    """FR-14 redacts ``url.query``; a refused query must store no client bytes.

    Keeping the raw string — whole or truncated — would make the bound a way to
    put an unredacted secret into an indexed field.
    """
    query = b"token=SECRET&" + b"&".join(b"k%03d=v" % i for i in range(600))
    doc = build_document(query_ctx(query), make_config())
    assert doc["url"]["query"] == "[SKIPPED]"
    assert doc["audit"]["request"]["query"] == {}
    assert "SECRET" not in json.dumps(doc)


def test_N2_3_the_bound_is_derived_from_the_capture_knobs() -> None:
    """The query bound is driven by ``max_query_bytes``, capped by the
    capture knobs.

    Tightening ``max_body_nodes``/``max_body_bytes`` tightens the query too;
    raising them cannot lift it, because ``max_query_bytes`` still applies.
    Only raising ``max_query_bytes`` itself does — asserted last.
    """
    tight_nodes = make_config(max_body_nodes=4)
    request = build_document(query_ctx(b"a=1&b=2&c=3&d=4&e=5"), tight_nodes)["audit"][
        "request"
    ]
    assert request["query_skipped"] == "too_complex"

    tight_bytes = make_config(max_body_bytes=16)
    request = build_document(query_ctx(b"a=" + b"x" * 32), tight_bytes)["audit"][
        "request"
    ]
    assert request["query_skipped"] == "too_complex"

    # ...and raising them does not lift the ceiling.
    generous = make_config(max_body_nodes=1_000_000, max_body_bytes=8 * 1024 * 1024)
    request = build_document(query_ctx(b"a&" * 4096), generous)["audit"]["request"]
    assert request["query_skipped"] == "too_complex"

    # The dedicated knob is the one that lifts it (added by the orchestrator
    # after this bound was first derived from the body knobs alone).
    widened = make_config(max_query_bytes=256 * 1024)
    request = build_document(query_ctx(b"a&" * 4096), widened)["audit"]["request"]
    assert "query_skipped" not in request


def test_N2_3_the_query_ceiling_does_not_shrink_a_form_body() -> None:
    """The ceilings are about the request *line*, not about form bodies.

    A 600-pair form body is well inside ``max_body_nodes`` and must still be
    captured — the query bound shares ``_query`` with it.
    """
    body = b"&".join(b"k%03d=v" % i for i in range(600))
    ctx = make_ctx(body=body, body_skipped=None, content_type=_FORM)
    request = build_document(ctx, make_config())["audit"]["request"]
    assert "body_skipped" not in request
    assert len(request["body"]) == 600


def test_N2_3_a_refused_query_is_counted() -> None:
    metrics = CountingMetrics()
    build_document(query_ctx(b"a&" * 4096), make_config(), metrics=metrics)
    assert metrics["audit_queries_skipped_total"] == 1
    # A dropped query is not a dropped body.
    assert metrics["audit_bodies_skipped_total"] == 0


def test_N2_3_the_form_body_path_does_not_re_encode_a_string_it_discards() -> None:
    """``_body_block`` wants the parsed mapping only; the rebuild was free work.

    A redacted 1 MiB form body used to be re-``urlencode``d in full and the
    result thrown away — request-path cost scaling with an attacker-sized body,
    for nothing.
    """
    query = b"a=1&password=hunter2"
    keys = frozenset({"password"})
    assert document_module._query(query, keys)[0] != ""
    rebuilt, parsed = document_module._query(query, keys, rebuild=False)
    assert rebuilt == ""
    assert parsed == {"a": "1", "password": "hunter2"}  # identity redact


# ===========================================================================
# REVIEW-2 N2-6 — a body that is not stored is counted
# ===========================================================================


def test_N2_6_a_body_over_the_node_cap_is_counted() -> None:
    """REVIEW-2 N2-6: nothing counted these, so an operator could not see them."""
    config = make_config()
    metrics = CountingMetrics()
    doc = build_document(
        json_ctx(_one_mib_of(b"[]", config.max_body_bytes)), config, metrics=metrics
    )
    assert doc["audit"]["request"]["body_skipped"] == "too_complex"
    assert metrics["audit_bodies_skipped_total"] == 1


@pytest.mark.parametrize(
    "ctx_kwargs",
    [
        {"body": b"hello", "body_skipped": None, "content_type": "text/plain"},
        {"body": b"\x89PNG", "body_skipped": "content_type", "content_type": "image/png"},
        {
            "body": b"--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nx\r\n--B--",
            "body_skipped": "content_type",
            "content_type": "multipart/form-data; boundary=B",
        },
    ],
)
def test_N2_6_a_body_the_denylist_cannot_be_applied_to_is_counted(
    ctx_kwargs: dict[str, Any],
) -> None:
    metrics = CountingMetrics()
    doc = build_document(make_ctx(**ctx_kwargs), make_config(), metrics=metrics)
    assert doc["audit"]["request"]["body_skipped"] == "content_type"
    assert metrics["audit_bodies_skipped_total"] == 1


@pytest.mark.parametrize("skipped", ["empty", "unread"])
def test_N2_6_a_body_that_never_existed_is_not_counted(skipped: str) -> None:
    """``empty``/``unread`` are not the package dropping anything.

    Counting them would put every ``GET`` into the counter and bury the signal
    it exists for.
    """
    metrics = CountingMetrics()
    doc = build_document(make_ctx(body_skipped=skipped), make_config(), metrics=metrics)
    assert doc["audit"]["request"]["body_skipped"] == skipped
    assert metrics["audit_bodies_skipped_total"] == 0


def test_N2_6_a_scrub_refusal_is_counted(real_enough: None) -> None:
    config = make_config(capture_text_bodies=True, max_scrub_bytes=64)
    metrics = CountingMetrics()
    ctx = make_ctx(body=b"k: v" * 100, body_skipped=None, content_type="text/plain")
    doc = build_document(ctx, config, metrics=metrics)
    assert doc["audit"]["request"]["body_skipped"] == "too_complex"
    assert metrics["audit_bodies_skipped_total"] == 1


def test_N2_6_a_raising_metrics_never_costs_the_document() -> None:
    """NFR-3: a caller-supplied counter must not take the audit record with it."""

    class Hostile:
        def inc(self, name: str, value: int = 1) -> None:
            raise RuntimeError("counters are broken")

        def set(self, name: str, value: float) -> None:
            raise RuntimeError("counters are broken")

    config = make_config()
    doc = build_document(
        json_ctx(_one_mib_of(b"[]", config.max_body_bytes)), config, metrics=Hostile()
    )
    assert doc["audit"]["request"]["body_skipped"] == "too_complex"


def test_N2_6_building_without_metrics_is_still_supported() -> None:
    """AGENTS.md pins ``build_document(ctx, config)``; ``metrics`` is optional."""
    doc = build_document(make_ctx(), make_config())
    assert doc["audit"]["request"]["body_skipped"] == "empty"


# ---------------------------------------------------------------------------
# Documented limitations, pinned (docs/redaction.md §4.3, §4.7).
#
# These assert today's behaviour so a documented gap cannot silently close or
# widen unnoticed. Each docstring says what a fix would look like.
# ---------------------------------------------------------------------------


@pytest.fixture
def real_redaction(monkeypatch: pytest.MonkeyPatch) -> None:
    """Undo this module's autouse identity stubs (a Phase 1 isolation choice).

    A limitation test about *redaction* must exercise the real thing.
    """
    from audit_logging import redact as redact_module

    monkeypatch.setattr(document_module, "redact", redact_module.redact)
    monkeypatch.setattr(document_module, "filter_headers", redact_module.filter_headers)
    monkeypatch.setattr(document_module, "normalize_key", redact_module.normalize_key)


def text_ctx(body: bytes, content_type: str = "text/plain") -> RequestContext:
    """A body on the FR-28 text path — stored only with capture_text_bodies."""
    return make_ctx(
        content_type=content_type,
        body=body,
        body_skipped=None,
        scope={"headers": [(b"content-type", content_type.encode())]},
    )


def _scrubbed(body: bytes, content_type: str = "text/plain", **cfg: Any) -> Any:
    config = make_config(capture_text_bodies=True, **cfg)
    return build_document(text_ctx(body, content_type), config)["audit"]["request"]


@pytest.mark.parametrize(
    ("name", "body", "secret"),
    [
        ("prose", b"please note the password is hunter2 and expires friday", b"hunter2"),
        ("namespaced xml", b"<wsse:Password>hunter2</wsse:Password>", b"hunter2"),
        ("multi-line value", b"password:\n  hunter2\n", b"hunter2"),
    ],
)
def test_LIMITATION_the_text_scrub_misses_these_shapes(
    name: str, body: bytes, secret: bytes
) -> None:
    """`docs/redaction.md` §4.7 — the opt-in scrub is pattern-based.

    `capture_text_bodies` trades safety for coverage: five regex patterns over
    an unparseable body. It catches `k=v`, `"k":"v"`, `k: v` and simple
    `<k>v</k>`, and misses everything here. That is why the default is off and
    the doc calls the scrub explicitly weaker than the structured path.

    Note `docs/redaction.md` overstates one case: **plain nested XML is
    caught**, because the `<k>v</k>` pattern is a regex over the whole text and
    nesting does not hide it. Only *namespacing* (`<wsse:Password>`) defeats
    it. Verified while writing this test; the doc should be narrowed.

    A fix would mean real per-format parsers (XML, YAML, CSV) with their own
    cost and attack surface. If one lands, flip the assertion for that format
    rather than deleting this test.
    """
    stored = _scrubbed(body).get("body_raw", "")
    assert secret.decode() in stored, f"{name}: expected the documented leak"


def test_LIMITATION_a_client_can_forge_the_redacted_literal(
    real_redaction: None,
) -> None:
    """`docs/redaction.md` §4.7 — `[REDACTED]` is not authenticated.

    A client can send the literal string and make a stored value
    indistinguishable from one the package redacted, so "this field was
    redacted" cannot be inferred from the value alone.

    A fix would need a marker a client cannot produce (a per-process nonce, or
    a parallel list of redacted paths).
    """
    body = b'{"note":"[REDACTED]","password":"hunter2"}'
    request = build_document(
        make_ctx(content_type="application/json", body=body, body_skipped=None),
        make_config(),
    )["audit"]["request"]
    assert request["body"] == {"note": "[REDACTED]", "password": "[REDACTED]"}


def test_LIMITATION_a_text_body_over_max_scrub_bytes_is_refused_not_scrubbed() -> None:
    """`docs/redaction.md` §4.7 — the scrub is bounded, and the bound wins.

    The scrub is a regex pass, so it recreates M-2's event-loop stall on a
    large body. Past `max_scrub_bytes` the body is refused as `too_complex`
    rather than half-scrubbed: no body is safer than a partly-scrubbed one.
    """
    request = _scrubbed(b"password=hunter2&" + b"x" * 40_000, max_scrub_bytes=1024)
    assert request["body_skipped"] == "too_complex"
    assert "body_raw" not in request and "body" not in request


def test_LIMITATION_control_characters_in_query_keys_are_not_normalised_away(
    real_redaction: None,
) -> None:
    """`docs/redaction.md` §4.3 (review N2-14).

    `normalize_key` strips `_`, `-` and `.` only. A control character embedded
    in a query key defeats the denylist exactly as whitespace does, so the
    value is stored in the clear. The key itself is sanitised for Lucene's
    sake (N-9), which is a separate concern from matching it.

    A fix means normalising the C0 range in `normalize_key` — cheap, and worth
    doing; this test should then flip to asserting redaction.
    """
    request = build_document(query_ctx(b"pass\x01word=hunter2"), make_config())["audit"][
        "request"
    ]
    assert "hunter2" in json.dumps(request["query"]), "the documented leak"


# ---------------------------------------------------------------------------
# N3-1 — distinct keys, not node count, are what redaction costs
# ---------------------------------------------------------------------------


def test_N3_1_a_body_of_many_distinct_keys_is_refused(real_redaction: None) -> None:
    """`REVIEW-3.md` N3-1 — the node cap measures the wrong axis.

    A repeated key is two dict lookups; a first-seen one costs ~1.4 us that no
    cache can amortise. `max_body_nodes` cannot tell them apart, and the client
    chooses which it sends: 9,999 nodes of 4,999 distinct keys measured
    **9.09 ms and was stored**, while 10,001 nodes of four repeated keys was
    0.16 ms and refused. `max_distinct_keys` bounds the axis that costs.
    """
    body = json.dumps({f"field_name_{i}": i for i in range(4999)}).encode()
    config = make_config()
    assert len(json.loads(body)) > config.max_distinct_keys

    request = build_document(
        make_ctx(content_type="application/json", body=body, body_skipped=None), config
    )["audit"]["request"]
    assert request["body_skipped"] == "too_complex"
    assert "body" not in request


def test_N3_1_repeated_keys_are_not_penalised(real_redaction: None) -> None:
    """The other half, and the reason the bound is on *distinct* keys.

    A bulk payload repeats its key names — that is what makes it bulk. Bounding
    total keys instead would refuse ordinary traffic to stop an attack that
    ordinary traffic does not resemble.
    """
    order = {"id": "A-1", "qty": 1, "sku": "S-1", "note": "pick"}
    body = json.dumps({"orders": [order] * 400}).encode()
    request = build_document(
        make_ctx(content_type="application/json", body=body, body_skipped=None),
        make_config(),
    )["audit"]["request"]
    assert "body" in request, "a bulk payload with repeated keys must still be stored"
    assert "body_skipped" not in request


def test_N3_1_a_wide_form_body_is_refused_before_it_is_parsed(
    real_redaction: None,
) -> None:
    """Refusing has to be cheap, or the refusal *is* the attack.

    Every form pair is a key, so the distinct-key budget is also a pair
    ceiling — applied before `_split_pairs` walks the body. Catching the
    budget exception afterwards also refuses, but only after paying to parse:
    9,999 pairs cost 6.45 ms to refuse that way, over the NFR-1 budget by
    itself. Applied up front it is 0.06 ms.
    """
    body = b"&".join(b"k%05d=v%05d" % (i, i) for i in range(9999))
    request = build_document(
        make_ctx(
            content_type="application/x-www-form-urlencoded",
            body=body,
            body_skipped=None,
        ),
        make_config(),
    )["audit"]["request"]
    assert request["body_skipped"] == "too_complex"


def test_N3_1_the_budget_is_not_applied_to_server_defined_structures(
    real_redaction: None,
) -> None:
    """`audit.path_params` keys come from the route template, not the client.

    Bounding them would be bounding the wrong thing: a route cannot declare
    thousands of parameters, and if it could, that is a server-side choice.
    """
    from audit_logging.document import _path_params
    from audit_logging.redact import DEFAULT_REDACT_KEYS

    wide = {f"p{i}": str(i) for i in range(5000)}
    assert len(_path_params({"path_params": wide}, DEFAULT_REDACT_KEYS)) == 5000
