"""Latency budget for the gateway hot path, enforced from ``bench/latency.py``.

Budget and why: ADR-1 / ROADMAP §1.3 gate the gateway at p95 < 15 ms and p99 < 50 ms added
latency with 200 concurrent streams on the reference runner. The in-process bench removes the
network, so its numbers are the gateway's own floor; we hold the floor to a tenth of the gate
for sequential calls (p99 < 5 ms) and to the gate itself under 200 concurrent streams. Measured
on the lane laptop (Apple silicon): sequential added p99 ~0.2 ms, concurrent added p99 ~3 ms,
so the test keeps >= 10x headroom against CI noise while still catching an accidental
blocking call (a single synchronous 5 ms stall on the hot path fails it). The Action
Gate variant (every agent policied, every response proposing a tool call that must be
decided) holds the same budget.
"""

from __future__ import annotations

import gc
import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

# Timing budget: ci/run.sh runs `serial` tests alone after the parallel suite, so other
# workers never share the CPU while it measures.
pytestmark = pytest.mark.serial

SEQUENTIAL_P99_MS = 5.0
CONCURRENT_P95_MS = 15.0
CONCURRENT_P99_MS = 50.0


def _bench() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "bench" / "latency.py"
    spec = importlib.util.spec_from_file_location("sibyl_gateway_bench_latency", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("actions", [False, True], ids=["plain", "action_gate"])
@pytest.mark.parametrize("stream", [False, True])
async def test_added_latency_stays_within_budget(stream: bool, actions: bool) -> None:
    """Best of three runs with the GC collected and frozen: a benchmark measures the code's
    floor, and a shared CI runner (or leftover server threads from earlier tests) adds noise
    that is not the gateway's. A genuine regression fails all three."""
    bench = _bench()
    results = []
    gc.collect()
    gc.freeze()
    try:
        for _ in range(3):
            result = await bench.run(n=600, concurrency=200, stream=stream, actions=actions)
            results.append(result)
            if (
                result["added_p99_ms"] < SEQUENTIAL_P99_MS
                and result["concurrent_added_p95_ms"] < CONCURRENT_P95_MS
                and result["concurrent_added_p99_ms"] < CONCURRENT_P99_MS
            ):
                return
    finally:
        gc.unfreeze()
    pytest.fail(f"latency budget exceeded in 3 runs: {results}")
