"""credentials API module (lane R): provider credentials, envelope-encrypted (D11, R55).

Implemented: list, create, rotate, revoke and verify (``routes.py``). Verify only enqueues a
``credential_probe`` job (B14): the probe runs in the worker, never inline in the api (SSRF
boundary), and the worker writes the ``credential.verified`` / ``credential.probe_failed`` rows.
"""

from sibyl_control.api._stubs import stub_router

from .routes import router as _router

router = stub_router("credentials", _router)
