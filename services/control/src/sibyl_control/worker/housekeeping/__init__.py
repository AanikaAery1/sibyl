"""Housekeeping loops (lane U), registered in ``worker/loops.py``:

``partitions`` (hourly partition_ensure_ahead; G1 blocker), ``retention`` (payload sweep under
the legal-hold predicate, hold expiry, partition drops), ``anchors`` (hourly signed anchors,
break-glass ``audit.anchor_now`` requests; exports and large verifications are jobs run by
``worker.jobs.audit`` over ``exports`` / ``verification``), ``erasure_exec``
(approved erasures to completed, with certificate and ledger entry) and ``erasure_ledger``
(off-database ledger back-fill, verification and signed head; R63).
"""
