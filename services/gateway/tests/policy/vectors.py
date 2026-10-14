"""Load the sibyl-schemas snapshot vectors in either generation (1.0 unsigned key set,
1.1 signed key-set chain + raw envelope cases)."""

from __future__ import annotations

import json
import os
from typing import Any

import pytest
from sibyl_gateway.policy.keychain import KeyChain
from sibyl_gateway.policy.verify import PinnedKeySet, parse_ts
from sibyl_schemas.golden import load_fixture


def snapshot_vectors() -> dict[str, Any]:
    vectors: dict[str, Any] = load_fixture("snapshot", "vectors.json")
    return vectors


def key_set_vectors() -> dict[str, Any]:
    """1.1 chain vectors; ``SIBYL_TEST_KEY_SET_VECTORS`` points at them before the merge."""
    try:
        vectors: dict[str, Any] = load_fixture("snapshot", "key_set_vectors.json")
        return vectors
    except FileNotFoundError:
        path = os.environ.get("SIBYL_TEST_KEY_SET_VECTORS")
        if not path:
            pytest.skip("key_set_vectors.json arrives with sibyl-schemas 1.1 (main)")
        with open(path, encoding="utf-8") as handle:
            loaded: dict[str, Any] = json.load(handle)
        return loaded


def verification_keys(vectors: dict[str, Any]) -> PinnedKeySet:
    key_set = vectors["key_set"]
    if "body" not in key_set:  # 1.0: unsigned {keys, next_key}
        return PinnedKeySet.from_document(key_set)
    genesis = key_set["body"]
    chain = KeyChain.from_pin_json(json.dumps(genesis["keys"][0]))
    issued = parse_ts(genesis["issued_at"])
    chain.accept(json.dumps(key_set), now=issued, persist=False)
    return chain.verification_keys(issued)
