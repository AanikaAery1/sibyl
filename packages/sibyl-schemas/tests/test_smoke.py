from typing import get_args

import pytest
import sibyl_schemas
from sibyl_schemas import jsonschema as sj
from sibyl_schemas.golden import golden_cases
from sibyl_schemas.models.snapshot import MachineScopeName
from sibyl_schemas.values import MACHINE_SCOPES, MONITOR_KEY_SCOPES


def test_frozen_contract_version() -> None:
    assert sibyl_schemas.__version__ == "1.1.0"
    assert sibyl_schemas.CONTRACT_TAG == "contracts-v1.1.0"
    assert set(sibyl_schemas.DOCUMENT_SCHEMAS) == set(sj.schema_names())


def test_golden_rejects_unknown_area() -> None:
    with pytest.raises(KeyError, match="unknown fixture area"):
        golden_cases("nonexistent")
    assert {c.area for c in golden_cases("handoff")} == {"handoff"}


def test_machine_scope_literal_matches_catalogue() -> None:
    # D53: monitor-bound keys are never in the gateway snapshot.
    assert set(get_args(MachineScopeName)) == {s.value for s in MACHINE_SCOPES - MONITOR_KEY_SCOPES}
