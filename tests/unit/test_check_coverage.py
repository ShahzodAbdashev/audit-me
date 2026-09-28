"""check coverage / check docs (FR-58). Agent F."""

from __future__ import annotations

import sys
import types
from collections.abc import Iterator
from typing import Any

import pytest

from audit_logging import check
from audit_logging.semantic import catalog as catalog_mod
from audit_logging.semantic import decorators, derive
from audit_logging.semantic.model import EventDef

DECORATED = EventDef("admin.user.updated", {"uz": "{actor} «{target}» ni tahrirladi"}, "admin", "high")
CATALOGED = EventDef("admin.user.deleted", {"uz": "{actor} o'chirdi"}, "admin", "critical", level="catalog")


class Route:
    def __init__(self, methods: set[str], path: str, endpoint: Any, summary: str | None = None,
                 include_in_schema: bool = True) -> None:
        self.methods, self.path, self.endpoint = methods, path, endpoint
        self.summary, self.include_in_schema = summary, include_in_schema


def _ep(event: EventDef | None = None) -> Any:
    def fn() -> None: ...
    if event is not None:
        setattr(fn, decorators.ATTRIBUTE, event)
    return fn


@pytest.fixture
def app_spec(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    mod = types.ModuleType("fake_cov_app")
    mod.app = types.SimpleNamespace(routes=[  # type: ignore[attr-defined]
        Route({"POST"}, "/users/{user_id}", _ep(DECORATED)),
        Route({"DELETE"}, "/users/{user_id}", _ep()),
        Route({"GET", "HEAD"}, "/stats/export", _ep(), summary="Export stats"),
        Route({"GET"}, "/docs", _ep(), include_in_schema=False),
        object(),  # a Mount-like thing with no methods
    ])
    monkeypatch.setitem(sys.modules, "fake_cov_app", mod)
    monkeypatch.setattr(decorators, "event_def_of", lambda ep: getattr(ep, decorators.ATTRIBUTE, None))
    monkeypatch.setattr(catalog_mod, "load_catalog", lambda path: {
        ("DELETE", "/users/{user_id}"): CATALOGED,
        ("POST", "/old"): CATALOGED,
    })
    yield "fake_cov_app:app"


def test_FR_58_coverage_counts_and_fails_over_max(app_spec: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert check.main(["coverage", app_spec, "--catalog", "c.json"]) == 1
    out = capsys.readouterr().out
    assert "3 routes · 1 decorator · 1 catalog · 1 derived (33.3 %)" in out
    assert "DERIVED  GET /stats/export" in out
    assert "ORPHAN   catalog: POST /old" in out
    assert "HEAD" not in out and "DERIVED  GET /docs" not in out


def test_FR_58_coverage_passes_under_max(app_spec: str) -> None:
    assert check.main(["coverage", app_spec, "--catalog", "c.json", "--max-derived", "50"]) == 0


def test_FR_58_coverage_without_catalog(app_spec: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert check.main(["coverage", app_spec, "--max-derived", "100"]) == 0
    assert "2 derived" in capsys.readouterr().out


def test_FR_58_reports_clearly_when_unbuilt(app_spec: str, monkeypatch: pytest.MonkeyPatch,
                                             capsys: pytest.CaptureFixture[str]) -> None:
    def stub(ep: Any) -> None:
        raise NotImplementedError

    monkeypatch.setattr(decorators, "event_def_of", stub)
    with pytest.raises(SystemExit) as exc:
        check.main(["coverage", app_spec])
    assert exc.value.code == 2
    assert "not implemented" in capsys.readouterr().out


def test_FR_58_docs_table(app_spec: str, monkeypatch: pytest.MonkeyPatch,
                          capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(derive, "default_labels", lambda: derive.Labels())
    monkeypatch.setattr(derive, "derive", lambda service, method, route, **k: EventDef(
        "svc.stat.exported", {"uz": "{actor} statistikani eksport qildi"}, "export", "normal", level="derived"))
    assert check.main(["docs", app_spec, "--catalog", "c.json"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "| method | route | level | code | category | risk | uz |"
    assert "| POST | /users/{user_id} | decorator | admin.user.updated | admin | high |" in lines[2]
    assert any("| DELETE | /users/{user_id} | catalog | admin.user.deleted |" in ln for ln in lines)
    assert any("| GET | /stats/export | derived | svc.stat.exported | export |" in ln for ln in lines)


def test_FR_58_docs_without_derive(app_spec: str, monkeypatch: pytest.MonkeyPatch,
                                   capsys: pytest.CaptureFixture[str]) -> None:
    def stub() -> derive.Labels:
        raise NotImplementedError

    monkeypatch.setattr(derive, "default_labels", stub)
    assert check.main(["docs", app_spec]) == 0
    assert "| GET | /stats/export | derived | — |" in capsys.readouterr().out


def test_FR_58_default_command_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    # No sub-command -> the 0.1 health check path (argparse still owns --leak).
    with pytest.raises(SystemExit):
        check.main(["--help"])


def test_FR_58_catalog_defaults_to_AUDIT_CATALOG_FILE(
    app_spec: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("AUDIT_CATALOG_FILE", "c.json")
    assert check.main(["coverage", app_spec, "--max-derived", "50"]) == 0
    assert "1 catalog" in capsys.readouterr().out


def test_FR_58_hidden_routes_are_reported_separately(
    app_spec: str, capsys: pytest.CaptureFixture[str]
) -> None:
    check.main(["coverage", app_spec, "--catalog", "c.json"])
    assert "HIDDEN   GET /docs" in capsys.readouterr().out
