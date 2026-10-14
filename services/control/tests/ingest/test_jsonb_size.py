"""The jsonb size estimate is an upper bound on PostgreSQL's own ``pg_column_size``."""

from __future__ import annotations

import json
import random
from typing import Any

import asyncpg
from sibyl_control.ingest.normalise.jsonb_size import jsonb_size
from sibyl_schemas.golden import golden_cases

from .conftest import ADMIN_DSN


def _random_doc(rng: random.Random, depth: int = 0) -> Any:
    kind = rng.choice(
        ["str", "int", "float", "bool", "null", "list", "dict"]
        if depth < 4
        else ["str", "int", "float"]
    )
    if kind == "str":
        return "".join(rng.choice("aé✓𝄞 xyz0") for _ in range(rng.randint(0, 40)))
    if kind == "int":
        return rng.choice([0, 1, -7, 299, 10**6, 2**53 - 1, -(10**15)])
    if kind == "float":
        return rng.choice([0.5, 1e-9, 1843.2, -3.14159, 123456.789012, 0.0455])
    if kind == "bool":
        return rng.random() < 0.5
    if kind == "null":
        return None
    if kind == "list":
        return [_random_doc(rng, depth + 1) for _ in range(rng.randint(0, 12))]
    return {f"k{i}": _random_doc(rng, depth + 1) for i in range(rng.randint(0, 12))}


async def test_estimate_is_an_upper_bound(ingest_dbname: str) -> None:
    rng = random.Random(20261011)  # noqa: S311  (reproducible test data)
    docs: list[Any] = [_random_doc(rng) for _ in range(400)]
    docs += [
        {"n": list(range(300))},
        {f"k{i}": i * 1.5 for i in range(150)},
        "x" * 3000,
        7,
        1.5,
        True,
    ]
    docs += [
        c.load()["attrs"] for c in golden_cases("ingest") if c.valid and c.schema == "sibyl-event/1"
    ]
    conn = await asyncpg.connect(ADMIN_DSN)
    try:
        actual = await conn.fetch(
            "SELECT pg_column_size(t::jsonb) AS n FROM unnest($1::text[]) WITH ORDINALITY u(t,"
            " o) ORDER BY o",
            [json.dumps(d) for d in docs],
        )
    finally:
        await conn.close()
    for doc, row in zip(docs, actual, strict=True):
        estimate = jsonb_size(doc)
        assert estimate >= row["n"], (doc, estimate, row["n"])
        assert estimate <= row["n"] * 2 + 64, (doc, estimate, row["n"])
