"""Typed identifiers — PLAN §17.1. Owned by agent H."""

from __future__ import annotations

import random

import pytest

from audit_logging.semantic.identifiers import luhn_check_digit, normalize, normalize_all
from audit_logging.semantic.model import IDENTIFIER_TYPES

JUNK: list[object] = [
    None, {}, {"a": 1}, [], b"32101801234567", bytearray(b"1"), 1.5, True, False,
    object(), "", " ", "x" * 1_000_000, "9" * 100_000, 10**400, -32101801234567, "٣٢١٠١٨٠١٢٣٤٥٦٧",
]


@pytest.mark.parametrize("kind", [*IDENTIFIER_TYPES, "email", "", None, 1])
@pytest.mark.parametrize("value", JUNK, ids=lambda v: type(v).__name__)
def test_never_raises_on_arbitrary_objects(kind: object, value: object) -> None:
    assert normalize(kind, value) is None  # type: ignore[arg-type]


@pytest.mark.parametrize("value, want", [
    ("32101801234567", "32101801234567"),
    ("321 018 0123 4567", "32101801234567"),
    ("3210-1801-2345-67", "32101801234567"),
    (32101801234567, "32101801234567"),
])
def test_pinpp_valid(value: object, want: str) -> None:
    assert normalize("pinpp", value) == want


@pytest.mark.parametrize("value", [
    "3210180123456", "321018012345678", "3210180123456A", "A2101801234567",
    "32101801234567\n", "+32101801234567", "32101801234567.0", "3210180123 456 7x",
])
def test_pinpp_invalid(value: str) -> None:
    assert normalize("pinpp", value) is None


def test_pinpp_random_lengths() -> None:
    rnd = random.Random(1)
    for _ in range(500):
        n = rnd.randint(1, 20)
        s = "".join(rnd.choice("0123456789") for _ in range(n))
        assert normalize("pinpp", s) == (s if n == 14 else None)


@pytest.mark.parametrize("value", [
    "90 123 45 67", "901234567", "0901234567", "998901234567", "+998901234567",
    "+998 (90) 123-45-67", "+998-90-123-45-67", "00998901234567", "(90) 123.45.67",
])
def test_msisdn_uzbek_forms(value: str) -> None:
    assert normalize("msisdn", value) == "+998901234567"


@pytest.mark.parametrize("value, want", [
    ("+14155552671", "+14155552671"),
    ("+7 916 123 45 67", "+79161234567"),
    ("+44 20 7946 0958", "+442079460958"),
    ("+12345678", "+12345678"),
    ("+123456789012345", "+123456789012345"),
    (901234567, "+998901234567"),
])
def test_msisdn_other_valid(value: object, want: str) -> None:
    assert normalize("msisdn", value) == want


@pytest.mark.parametrize("value", [
    "+1234567", "+1234567890123456", "+99890123456", "+9989012345678", "12345678",
    "90123456", "1901234567", "99890123456", "9989012345678", "+998 90 123 45 6a",
    "++998901234567", "998+901234567", "phone", "+", "0", "+998",
    "+0012345678", "000012345678",  # E.164 country codes start with 1-9
])
def test_msisdn_invalid(value: str) -> None:
    assert normalize("msisdn", value) is None


@pytest.mark.parametrize("value", ["AA1234567", "aa1234567", "aa 1234567", " Ab 123 45 67 ", "AB-1234567"])
def test_passport_valid(value: str) -> None:
    assert normalize("passport", value) == value.replace(" ", "").replace("-", "").upper()


@pytest.mark.parametrize("value", [
    "A1234567", "AAA1234567", "AA123456", "AA12345678", "1A1234567", "АА1234567",  # Cyrillic
    "AA123456X", "",
])
def test_passport_invalid(value: str) -> None:
    assert normalize("passport", value) is None


def _luhn_ok(s: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(s)):
        d = int(ch) * (2 if i % 2 else 1)
        total += d - 9 if d > 9 else d
    return total % 10 == 0


def test_luhn_known_imei() -> None:
    assert luhn_check_digit("49015420323751") == "8"
    assert luhn_check_digit("35209900176148") == "1"


def test_imei_valid_bad_and_completion() -> None:
    assert normalize("imei", "490154203237518") == "490154203237518"
    assert normalize("imei", "49-015420-323751-8") == "490154203237518"
    assert normalize("imei", "49 015420 323751/8") == "490154203237518"
    assert normalize("imei", "49015420323751") == "490154203237518"
    assert normalize("imei", "490154203237517") is None
    for bad in ("4901542032375", "4901542032375180", "49015420323751X", "IMEI490154203237518"):
        assert normalize("imei", bad) is None


def test_imei_random_property() -> None:
    rnd = random.Random(2)
    for _ in range(500):
        body = "".join(rnd.choice("0123456789") for _ in range(14))
        full = body + luhn_check_digit(body)
        assert _luhn_ok(full)
        assert normalize("imei", body) == full
        assert normalize("imei", full) == full
        wrong = body + str((int(full[-1]) + rnd.randint(1, 9)) % 10)
        assert normalize("imei", wrong) is None


def test_normalize_all() -> None:
    ok, bad = normalize_all({
        "pinpp": "32101801234567", "msisdn": "90 123 45 67", "passport": "aa1234567",
        "imei": "12345", "email": "a@b.c",
    })
    assert ok == {"pinpp": "32101801234567", "msisdn": "+998901234567", "passport": "AA1234567"}
    assert bad == ["imei", "email"]


@pytest.mark.parametrize("values", [None, [], "pinpp", b"x", 5, {1: "x", None: None}])
def test_normalize_all_never_raises(values: object) -> None:
    ok, bad = normalize_all(values)  # type: ignore[arg-type]
    assert ok == {}
    assert all(isinstance(k, str) for k in bad)


def test_normalize_all_bounded() -> None:
    ok, bad = normalize_all({f"k{i}": i for i in range(10_000)})
    assert ok == {} and len(bad) <= 32
