"""Async jobs worker loop (chair ruling B14, integration lane INT-1).

``tick`` claims runnable ``sibyl.job`` rows per tenant with SKIP LOCKED under a lease, runs them
outside any transaction and finishes each fenced by its attempt count (``runner``). Handlers:
``credential_probe`` (``probe``, SSRF-guarded through ``net``), ``audit_verify`` /
``audit_export`` (``audit``, over lane U's housekeeping code once merged).
"""

from .runner import tick

__all__ = ["tick"]
