"""Typed identifier normalisation (PLAN §17.1). OWNER: agent H.

Canonical forms (anything that does not normalise is REJECTED, never stored raw
in the typed field — it may still go to audit.detail):

  pinpp     14 digits (Uzbek personal number). Strip spaces/dashes. Exactly 14 digits.
  msisdn    E.164 with '+'. Uzbek national forms normalise to +998:
            "90 123 45 67", "901234567", "0901234567", "998901234567",
            "+998 (90) 123-45-67" -> "+998901234567". Other countries: accept
            "+<8..15 digits>" as is. 9-digit national numbers assume +998.
  passport  2 Latin letters + 7 digits, upper-cased ("aa 1234567" -> "AA1234567").
  imei      15 digits with a valid Luhn check digit (14 digits -> append the
            computed check digit). Strip spaces/dashes/slashes.
"""

from __future__ import annotations

import re
from typing import Mapping

from .model import IDENTIFIER_TYPES

#: Longer input is rejected before any regex runs (request path stays bounded).
_MAX_INPUT = 64

_PINPP = re.compile(r"[0-9]{14}")
_PASSPORT = re.compile(r"[A-Z]{2}[0-9]{7}")
_DIGITS = re.compile(r"[0-9]+")
_INTL = re.compile(r"\+([1-9][0-9]{7,14})")


def _text(value: object) -> str | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        if value < 0 or value.bit_length() > 64:
            return None
        return str(value)
    if isinstance(value, str) and len(value) <= _MAX_INPUT:
        return value
    return None


def _strip(value: str, chars: str) -> str:
    return value.translate({ord(c): None for c in chars})


def luhn_check_digit(digits14: str) -> str:
    """The Luhn check digit for a 14-digit IMEI body."""
    total = 0
    for i, ch in enumerate(reversed(digits14)):
        d = int(ch)
        if i % 2 == 0:  # the digit next to the check digit is doubled
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def _pinpp(s: str) -> str | None:
    s = _strip(s, " -")
    return s if _PINPP.fullmatch(s) else None


def _msisdn(s: str) -> str | None:
    s = _strip(s, " -().\t")
    if s.startswith("00"):
        s = "+" + s[2:]
    if s.startswith("+"):
        m = _INTL.fullmatch(s)
        if m is None or (m.group(1).startswith("998") and len(m.group(1)) != 12):
            return None
        return s
    if not _DIGITS.fullmatch(s):
        return None
    if len(s) == 9:
        return "+998" + s
    if len(s) == 10 and s.startswith("0"):
        return "+998" + s[1:]
    if len(s) == 12 and s.startswith("998"):
        return "+" + s
    return None


def _passport(s: str) -> str | None:
    s = _strip(s, " -").upper()
    return s if _PASSPORT.fullmatch(s) else None


def _imei(s: str) -> str | None:
    s = _strip(s, " -/")
    if not _DIGITS.fullmatch(s):
        return None
    if len(s) == 14:
        return s + luhn_check_digit(s)
    if len(s) == 15 and luhn_check_digit(s[:14]) == s[14]:
        return s
    return None


_NORMALIZERS = {"pinpp": _pinpp, "msisdn": _msisdn, "passport": _passport, "imei": _imei}


def normalize(kind: str, value: object) -> str | None:
    """Canonical string, or None when ``value`` is not a valid ``kind``. Never raises;
    unknown ``kind`` -> None."""
    try:
        fn = _NORMALIZERS.get(kind) if isinstance(kind, str) else None
        text = _text(value)
        if fn is None or text is None:
            return None
        return fn(text)
    except Exception:  # noqa: BLE001 - request path never raises
        return None


def normalize_all(values: Mapping[str, object]) -> tuple[dict[str, str], list[str]]:
    """(accepted {kind: canonical}, rejected kinds). Kinds not in IDENTIFIER_TYPES are rejected."""
    accepted: dict[str, str] = {}
    rejected: list[str] = []
    try:
        raw: object = values  # callers may pass anything
        if not isinstance(raw, Mapping):
            return accepted, rejected
        for i, (kind, value) in enumerate(raw.items()):
            if i >= 32:  # ponytail: bounded; a caller never has more than 4 real kinds
                break
            name = kind if isinstance(kind, str) else type(kind).__name__
            canonical = normalize(kind, value) if name in IDENTIFIER_TYPES else None
            if canonical is None:
                rejected.append(name[:_MAX_INPUT])
            else:
                accepted[name] = canonical
    except Exception:  # noqa: BLE001 - request path never raises
        pass
    return accepted, rejected
