"""FR-35 — the built-in shipper, without a cluster.

The shipper's whole point is that it does not change the promise the package
makes: records reach a local file first, and Elasticsearch being unreachable
must not reach the application. These tests hold it to that.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from audit_logging.config import AuditConfig
from audit_logging.metrics import InMemoryMetrics
from audit_logging.shipper import ElasticsearchShipper, _pid_is_alive


def cfg(tmp_path: Path, **kw: Any) -> AuditConfig:
    values: dict[str, Any] = {
        "service_name": "ship-api",
        "log_dir": tmp_path,
        "elasticsearch_url": "http://127.0.0.1:59999",  # nothing listens here
        "ship_interval_seconds": 0.05,
    }
    values.update(kw)
    return AuditConfig(**values)


class FakeResponse:
    def __init__(self, status: int = 200, body: dict | None = None) -> None:
        self.status_code = status
        self._body = body if body is not None else {"errors": False, "items": []}
        self.text = json.dumps(self._body)

    def json(self) -> dict:
        return self._body


class FakeClient:
    """Records what would have been sent."""

    def __init__(self, response: FakeResponse | None = None) -> None:
        self.posts: list[bytes] = []
        self.puts: list[str] = []
        self._response = response or FakeResponse()

    async def post(self, path: str, content: bytes = b"", **kw: Any) -> FakeResponse:
        self.posts.append(content)
        return self._response

    async def put(self, path: str, **kw: Any) -> FakeResponse:
        self.puts.append(path)
        return FakeResponse()

    async def aclose(self) -> None:
        return None

    @property
    def lines(self) -> list[dict]:
        out = []
        for payload in self.posts:
            for raw in payload.split(b"\n"):
                if raw.strip() and b'"create"' not in raw:
                    out.append(json.loads(raw))
        return out


def write_log(tmp_path: Path, pid: int, count: int, name: str = "ship-api") -> Path:
    path = tmp_path / f"{name}-{pid}.jsonl"
    with path.open("w") as fh:
        for i in range(count):
            fh.write(json.dumps({"n": i, "trace": {"id": f"t{i}"}}) + "\n")
    return path


async def test_FR_35_ships_the_lines_the_sink_already_wrote(tmp_path: Path) -> None:
    import os

    write_log(tmp_path, os.getpid(), 3)
    shipper = ElasticsearchShipper(cfg(tmp_path), InMemoryMetrics())
    client = FakeClient()
    shipper._client = client
    shipper._bootstrapped = True
    await shipper._tick()
    assert [d["n"] for d in client.lines] == [0, 1, 2]


async def test_FR_35_a_second_pass_does_not_resend(tmp_path: Path) -> None:
    """Progress is by (device, inode), so a rotation cannot cause a replay."""
    import os

    write_log(tmp_path, os.getpid(), 3)
    shipper = ElasticsearchShipper(cfg(tmp_path), InMemoryMetrics())
    shipper._client = FakeClient()
    shipper._bootstrapped = True
    await shipper._tick()
    client = FakeClient()
    shipper._client = client
    await shipper._tick()
    assert client.lines == [], "already-shipped lines were sent again"


async def test_FR_35_a_partial_line_is_left_for_the_next_tick(tmp_path: Path) -> None:
    """The sink may be mid-write; half a document must never be shipped."""
    import os

    path = tmp_path / f"ship-api-{os.getpid()}.jsonl"
    path.write_text('{"n":0}\n{"n":1}\n{"n":2,"incompl')
    shipper = ElasticsearchShipper(cfg(tmp_path), InMemoryMetrics())
    client = FakeClient()
    shipper._client = client
    shipper._bootstrapped = True
    await shipper._tick()
    assert [d["n"] for d in client.lines] == [0, 1]


async def test_FR_35_an_unreachable_cluster_is_survivable(tmp_path: Path) -> None:
    """The real failure mode. Nothing raises; the offset does not advance, so
    the lines are still there when the cluster comes back."""
    import os

    write_log(tmp_path, os.getpid(), 5)
    metrics = InMemoryMetrics()
    shipper = ElasticsearchShipper(cfg(tmp_path), metrics)
    shipper._bootstrapped = True
    await shipper._tick()  # nothing is listening on port 59999
    assert shipper._state == {} or all(v == 0 for v in shipper._state.values())

    client = FakeClient()
    shipper._client = client
    await shipper._tick()
    assert [d["n"] for d in client.lines] == [0, 1, 2, 3, 4], "records were lost"


async def test_FR_35_it_refuses_to_ship_until_the_template_exists(
    tmp_path: Path,
) -> None:
    """D-11 is unrecoverable, so this is the one failure it will not push past.

    Shipping into a cluster without the template creates a data stream with a
    dynamic mapping, and only a reindex fixes that.
    """
    import os

    write_log(tmp_path, os.getpid(), 2)

    class RefusingClient(FakeClient):
        async def put(self, path: str, **kw: Any) -> FakeResponse:
            self.puts.append(path)
            return FakeResponse(400, {"error": "nope"})

    shipper = ElasticsearchShipper(cfg(tmp_path), InMemoryMetrics())
    client = RefusingClient()
    shipper._client = client
    await shipper._tick()
    assert shipper._bootstrapped is False
    assert client.posts == [], "shipped despite the template install failing"


async def test_FR_35_does_not_steal_a_live_workers_file(tmp_path: Path) -> None:
    """One file per PID, several workers per pod. Shipping another live
    worker's file would duplicate every one of its records."""
    import os

    write_log(tmp_path, os.getpid(), 2)
    write_log(tmp_path, 1, 2)  # pid 1 is alive in every namespace
    shipper = ElasticsearchShipper(cfg(tmp_path), InMemoryMetrics())
    claimed = {p.name for p in shipper._claimable_files()}
    assert f"ship-api-{os.getpid()}.jsonl" in claimed
    assert "ship-api-1.jsonl" not in claimed


async def test_FR_35_adopts_a_dead_workers_file(tmp_path: Path) -> None:
    """...but a crashed worker's tail must not sit on disk forever."""
    dead = 2**22 - 1  # above /proc/sys/kernel/pid_max on any normal system
    write_log(tmp_path, dead, 2)
    shipper = ElasticsearchShipper(cfg(tmp_path), InMemoryMetrics())
    assert not _pid_is_alive(dead)
    assert f"ship-api-{dead}.jsonl" in {p.name for p in shipper._claimable_files()}


async def test_FR_35_a_rejected_document_does_not_block_the_ones_behind_it(
    tmp_path: Path,
) -> None:
    """A document Elasticsearch will never accept must not wedge the stream."""
    import os

    write_log(tmp_path, os.getpid(), 3)
    metrics = InMemoryMetrics()
    shipper = ElasticsearchShipper(cfg(tmp_path), metrics)
    shipper._bootstrapped = True
    shipper._client = FakeClient(
        FakeResponse(200, {"errors": True, "items": [{"create": {"status": 400, "error": {"reason": "bad"}}}]})
    )
    await shipper._tick()
    assert metrics.snapshot().get("audit_ship_rejected_total", 0) >= 1
    # The offset advanced, so the next tick moves on rather than retrying.
    assert any(v > 0 for v in shipper._state.values())


def test_FR_35_no_shipper_without_a_url(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="elasticsearch_url"):
        ElasticsearchShipper(AuditConfig(service_name="s", log_dir=tmp_path))
