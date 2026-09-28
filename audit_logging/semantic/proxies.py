"""Client IP through trusted proxies + session/trace headers (FR-45, FR-46). OWNER: agent I.

Client IP (FR-46): if the transport peer is inside AUDIT_TRUSTED_PROXIES (CIDRs,
comma-separated), walk X-Forwarded-For right-to-left skipping trusted hops and take
the first untrusted address; else X-Real-IP if the peer is trusted; else the peer.
Invalid addresses are skipped. Nothing is trusted when the setting is empty
(= 0.1 behaviour: client.ip is the peer, ip_source "peer").

Headers (FR-45): X-Session-Id -> audit.session.id ; X-Trace-Id (preferred) or
X-Request-ID -> trace.id (0.1 already reads X-Request-ID; X-Trace-Id wins when both
are present and well-formed: <= 200 printable ASCII chars, no spaces).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Sequence

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_trusted(spec: str | Sequence[str] | None) -> tuple[Network, ...]:
    """CIDR list -> networks; bare IPs become /32 or /128. Invalid entries raise ValueError
    (configuration: fail at startup)."""
    if spec is None:
        return ()
    items = spec.split(",") if isinstance(spec, str) else spec
    # strict=False: "10.0.0.1/8" means the /8 the operator obviously meant.
    return tuple(ipaddress.ip_network(s.strip(), strict=False) for s in items if s.strip())


def _ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    value = value.strip()
    if value.startswith("[") and "]" in value:  # "[::1]:443" / "[::1]"
        value = value[1:value.index("]")]
    elif value.count(":") == 1:  # "1.2.3.4:5678"
        value = value.split(":", 1)[0]
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    mapped = getattr(addr, "ipv4_mapped", None)  # ::ffff:1.2.3.4 -> 1.2.3.4
    return mapped if mapped is not None else addr


def _trusted(addr: ipaddress.IPv4Address | ipaddress.IPv6Address, nets: tuple[Network, ...]) -> bool:
    return any(addr.version == n.version and addr in n for n in nets)


def _header(headers: Sequence[tuple[bytes, bytes]], name: bytes) -> str | None:
    for k, v in headers:
        if k == name:
            return v.decode("latin-1")
    return None


@dataclass(frozen=True)
class ClientIP:
    ip: str | None
    source: str                 # one of IP_SOURCES
    forwarded_chain: str | None # raw X-Forwarded-For when it was consulted


def resolve_client_ip(
    peer: str | None, headers: Sequence[tuple[bytes, bytes]], trusted: tuple[Network, ...]
) -> ClientIP:
    """Pure; never raises."""
    try:
        peer_addr = _ip(peer) if peer else None
        if not trusted or peer_addr is None or not _trusted(peer_addr, trusted):
            return ClientIP(peer, "peer", None)
        # Multiple XFF headers are one list in arrival order (RFC 7230 §3.2.2).
        chain = ", ".join(v.decode("latin-1") for k, v in headers if k == b"x-forwarded-for")
        if chain.strip():
            hops = [a for a in map(_ip, chain.split(",")) if a is not None]
            for addr in reversed(hops):
                if not _trusted(addr, trusted):
                    return ClientIP(str(addr), "x_forwarded_for", chain)
            if hops:  # every hop trusted: the leftmost is the originating client
                return ClientIP(str(hops[0]), "x_forwarded_for", chain)
        real = _header(headers, b"x-real-ip")
        real_addr = _ip(real) if real else None
        if real_addr is not None:
            return ClientIP(str(real_addr), "x_real_ip", chain or None)
        return ClientIP(peer, "peer", chain or None)
    except Exception:
        return ClientIP(peer, "peer", None)


def header_ids(headers: Sequence[tuple[bytes, bytes]]) -> tuple[str | None, str | None]:
    """(session_id, trace_id) from the raw ASGI headers; invalid values -> None."""
    try:
        session = _valid(_header(headers, b"x-session-id"))
        trace = _valid(_header(headers, b"x-trace-id")) or _valid(_header(headers, b"x-request-id"))
        return session, trace
    except Exception:
        return None, None


def _valid(value: str | None) -> str | None:
    """<= 200 printable ASCII, no spaces (so 0x21..0x7e)."""
    if value and len(value) <= 200 and all("!" <= c <= "~" for c in value):
        return value
    return None
