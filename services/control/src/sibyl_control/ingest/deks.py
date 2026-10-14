"""Re-export of the kernel DEK convention (B11 moved it to ``core.crypto.deks``).

Kept only so modules written against the old path (lane U housekeeping) keep importing the same
objects; new code imports ``sibyl_control.core.crypto.deks``. Nothing is defined here.
"""

from __future__ import annotations

from ..core.crypto.deks import (
    DekUnavailable,
    KeyShredded,
    PgDekProvider,
    dek_wrap_aad,
    wrap_dek,
)

__all__ = ["DekUnavailable", "KeyShredded", "PgDekProvider", "dek_wrap_aad", "wrap_dek"]
