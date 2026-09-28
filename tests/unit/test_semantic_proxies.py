"""FR-45 / FR-46: client IP through trusted proxies, session/trace headers."""

from __future__ import annotations

import pytest

from audit_logging.semantic.model import IP_SOURCES
from audit_logging.semantic.proxies import ClientIP, header_ids, parse_trusted, resolve_client_ip

T = parse_trusted("10.0.0.0/8, 192.168.1.1, fd00::/8")


def h(**kw: str) -> list[tuple[bytes, bytes]]:
    return [(k.replace("_", "-").encode(), v.encode()) for k, v in kw.items()]


def test_parse_trusted() -> None:
    assert [str(n) for n in T] == ["10.0.0.0/8", "192.168.1.1/32", "fd00::/8"]
    assert str(parse_trusted(["::1"])[0]) == "::1/128"
    assert parse_trusted(None) == () == parse_trusted("") == parse_trusted(" , ")
    with pytest.raises(ValueError):
        parse_trusted("10.0.0.0/8,not-an-ip")


def test_nothing_trusted_is_01_behaviour() -> None:
    r = resolve_client_ip("10.0.0.1", h(x_forwarded_for="8.8.8.8"), ())
    assert r == ClientIP("10.0.0.1", "peer", None)


def test_spoof_from_untrusted_peer_ignored() -> None:
    r = resolve_client_ip("203.0.113.9", h(x_forwarded_for="8.8.8.8", x_real_ip="8.8.4.4"), T)
    assert r == ClientIP("203.0.113.9", "peer", None)


def test_right_to_left_skips_trusted_and_invalid() -> None:
    chain = "1.1.1.1, 8.8.8.8, garbage, 10.1.2.3"
    r = resolve_client_ip("10.0.0.1", h(x_forwarded_for=chain), T)
    assert r == ClientIP("8.8.8.8", "x_forwarded_for", chain)  # client-prepended 1.1.1.1 ignored


def test_all_hops_trusted_takes_leftmost() -> None:
    r = resolve_client_ip("10.0.0.1", h(x_forwarded_for="10.12.4.88, 10.0.0.2"), T)
    assert (r.ip, r.source) == ("10.12.4.88", "x_forwarded_for")


def test_multiple_xff_headers_joined() -> None:
    hs = [(b"x-forwarded-for", b"8.8.8.8"), (b"x-forwarded-for", b"10.0.0.5")]
    r = resolve_client_ip("10.0.0.1", hs, T)
    assert (r.ip, r.forwarded_chain) == ("8.8.8.8", "8.8.8.8, 10.0.0.5")


def test_x_real_ip_only_when_peer_trusted() -> None:
    assert resolve_client_ip("192.168.1.1", h(x_real_ip="8.8.4.4"), T) == ClientIP("8.8.4.4", "x_real_ip", None)
    assert resolve_client_ip("192.168.1.2", h(x_real_ip="8.8.4.4"), T).source == "peer"


def test_invalid_everything_falls_back_to_peer() -> None:
    r = resolve_client_ip("10.0.0.1", h(x_forwarded_for="nope, ,", x_real_ip="bad"), T)
    assert (r.ip, r.source) == ("10.0.0.1", "peer")


def test_ipv6_and_ports() -> None:
    r = resolve_client_ip("fd00::1", h(x_forwarded_for="[2001:db8::7]:443, 1.2.3.4:5678, fd00::2"), T)
    assert r.ip == "1.2.3.4"
    r = resolve_client_ip("::ffff:10.0.0.1", h(x_forwarded_for="2001:db8::7"), T)  # v4-mapped peer
    assert r.ip == "2001:db8::7"


def test_never_raises() -> None:
    assert resolve_client_ip(None, [], T) == ClientIP(None, "peer", None)
    assert resolve_client_ip("x", None, T).source == "peer"  # type: ignore[arg-type]
    assert resolve_client_ip("10.0.0.1", [(b"x-forwarded-for", b"\xff\xfe")], T).source == "peer"
    assert resolve_client_ip("10.0.0.1", None, T).source == "peer"  # type: ignore[arg-type]
    for peer in ("10.0.0.1", "8.8.8.8", None):
        assert resolve_client_ip(peer, h(x_forwarded_for="1.1.1.1"), T).source in IP_SOURCES


def test_header_ids() -> None:
    assert header_ids(h(x_session_id="s1", x_trace_id="t1", x_request_id="r1")) == ("s1", "t1")
    assert header_ids(h(x_request_id="r1")) == (None, "r1")
    assert header_ids(h(x_trace_id="has space", x_request_id="r1")) == (None, "r1")
    assert header_ids(h(x_session_id="x" * 201, x_trace_id="x" * 200)) == (None, "x" * 200)
    assert header_ids([(b"x-session-id", "é".encode()), (b"x-trace-id", b"a\tb")]) == (None, None)
    assert header_ids([]) == (None, None)
    assert header_ids(None) == (None, None)  # type: ignore[arg-type]
