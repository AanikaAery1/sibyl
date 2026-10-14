from __future__ import annotations

import pytest

from .support import TestSigner


@pytest.fixture
def signer() -> TestSigner:
    return TestSigner()
