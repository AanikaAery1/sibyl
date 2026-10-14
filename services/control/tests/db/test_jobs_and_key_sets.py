"""Migration 0016 (INT-1): the ``job`` table (B14) and the signing-key rotation chain (B10).

* ``job``: tenant-scoped under RLS, the api may only enqueue (``queued``), the worker moves it
  through the ``job`` state machine, at most one open job per subject, stable error codes only;
* ``outbox`` accepts the ``job`` topic;
* ``signing_key`` has a pre-published ``next`` state (one per purpose);
* ``signing_key_set`` keeps every issued set, immutable, its document bound to its row.
"""

from __future__ import annotations

import json
import secrets
import uuid

import asyncpg
import pytest

from .conftest import Conn
from .fixtures import TenantFixture, populate_tenant


@pytest.fixture(scope="module")
def fx(admin: Conn) -> TenantFixture:
    return populate_tenant(admin, "int1-jobs")


def _enqueue(conn: Conn, tenant: uuid.UUID, **extra: object) -> uuid.UUID:
    cols = {
        "tenant_id": tenant,
        "kind": "credential_probe",
        "params": json.dumps({"credential_id": str(uuid.uuid4())}),
        "requested_by": uuid.uuid4(),
        "requested_by_kind": "human",
        **extra,
    }
    names = ", ".join(cols)
    marks = ", ".join(f"${i}" for i in range(1, len(cols) + 1))
    return conn.fetchval(
        f"INSERT INTO sibyl.job ({names}) VALUES ({marks}) RETURNING id",  # noqa: S608
        *cols.values(),
    )


def test_app_enqueues_but_cannot_move_a_job(fx: TenantFixture, roles: dict[str, Conn]) -> None:
    app = roles["sibyl_app"]
    with app.tx(fx.tenant_id, rollback=True):
        job = _enqueue(app, fx.tenant_id)
        row = app.fetchrow("SELECT state, attempts, lease_until FROM sibyl.job WHERE id = $1", job)
        assert (row["state"], row["attempts"], row["lease_until"]) == ("queued", 0, None)
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            app.execute("UPDATE sibyl.job SET state = 'running' WHERE id = $1", job)


def test_app_cannot_enqueue_a_finished_job(fx: TenantFixture, roles: dict[str, Conn]) -> None:
    app = roles["sibyl_app"]
    with app.tx(fx.tenant_id, rollback=True), pytest.raises(asyncpg.InsufficientPrivilegeError):
        _enqueue(app, fx.tenant_id, state="done")


def test_worker_follows_the_job_state_machine(fx: TenantFixture, roles: dict[str, Conn]) -> None:
    worker = roles["sibyl_worker"]
    with worker.tx(fx.tenant_id, rollback=True):
        job = _enqueue(worker, fx.tenant_id, requested_by=None, requested_by_kind="system")
        worker.execute(
            "UPDATE sibyl.job SET state = 'running', attempts = 1, started_at = now(),"
            " lease_until = now() + interval '1 minute' WHERE id = $1",
            job,
        )
        worker.execute(
            "UPDATE sibyl.job SET state = 'queued', lease_until = NULL,"
            " run_after = now() + interval '2 seconds' WHERE id = $1",
            job,
        )
        worker.execute(
            "UPDATE sibyl.job SET state = 'running', attempts = 2,"
            " lease_until = now() + interval '1 minute' WHERE id = $1",
            job,
        )
        worker.execute(
            "UPDATE sibyl.job SET state = 'done', lease_until = NULL, finished_at = now(),"
            ' result = \'{"outcome": "verified"}\' WHERE id = $1',
            job,
        )
        with pytest.raises(asyncpg.PostgresError, match="invalid_transition"):
            worker.execute(
                "UPDATE sibyl.job SET state = 'queued', finished_at = NULL WHERE id = $1", job
            )


def test_a_queued_job_cannot_jump_to_done(fx: TenantFixture, roles: dict[str, Conn]) -> None:
    worker = roles["sibyl_worker"]
    with worker.tx(fx.tenant_id, rollback=True):
        job = _enqueue(worker, fx.tenant_id)
        with pytest.raises(asyncpg.PostgresError, match="invalid_transition"):
            worker.execute(
                "UPDATE sibyl.job SET state = 'done', finished_at = now() WHERE id = $1", job
            )


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("error", "Upstream said: 401 Unauthorized"),
        ("kind", "crypto_mining"),
        ("max_attempts", 99),
        ("params", '["not", "an", "object"]'),
        ("requested_by_kind", "agent"),
    ],
)
def test_job_constraints(
    fx: TenantFixture, roles: dict[str, Conn], column: str, value: object
) -> None:
    worker = roles["sibyl_worker"]
    with worker.tx(fx.tenant_id, rollback=True), pytest.raises(asyncpg.CheckViolationError):
        if column == "error":
            job = _enqueue(worker, fx.tenant_id)
            worker.execute("UPDATE sibyl.job SET error = $2 WHERE id = $1", job, value)
        else:
            _enqueue(worker, fx.tenant_id, **{column: value})


def test_one_open_job_per_subject(fx: TenantFixture, roles: dict[str, Conn]) -> None:
    app = roles["sibyl_app"]
    subject = uuid.uuid4()
    with app.tx(fx.tenant_id, rollback=True):
        _enqueue(app, fx.tenant_id, subject_kind="provider_credential", subject_id=subject)
        with pytest.raises(asyncpg.UniqueViolationError):
            _enqueue(app, fx.tenant_id, subject_kind="provider_credential", subject_id=subject)


def test_jobs_are_tenant_isolated(fx: TenantFixture, roles: dict[str, Conn], admin: Conn) -> None:
    other = populate_tenant(admin, "int1-jobs-other")
    app = roles["sibyl_app"]
    with app.tx(fx.tenant_id, rollback=True):
        job = _enqueue(app, fx.tenant_id)
        assert app.fetchval("SELECT count(*) FROM sibyl.job WHERE id = $1", job) == 1
    with app.tx(other.tenant_id, rollback=True):
        assert (
            app.fetchval("SELECT count(*) FROM sibyl.job WHERE tenant_id = $1", fx.tenant_id) == 0
        )


def test_outbox_accepts_the_job_topic(fx: TenantFixture, roles: dict[str, Conn]) -> None:
    app = roles["sibyl_app"]
    with app.tx(fx.tenant_id, rollback=True):
        app.execute(
            "INSERT INTO sibyl.outbox (tenant_id, topic, event_type, aggregate_kind, aggregate_id,"
            " payload, idempotency_key) VALUES ($1, 'job', 'job.requested', 'job', $2, '{}', $3)",
            fx.tenant_id,
            uuid.uuid4(),
            secrets.token_hex(8),
        )


# --- signing keys (B10) ----------------------------------------------------------------------


def _key(admin: Conn, kid: str, state: str, purpose: str = "agent_token") -> None:
    admin.execute(
        "INSERT INTO sibyl.signing_key (kid, purpose, public_key, private_key_ref, state)"
        " VALUES ($1, $2, $3, 'env:NONE', $4)",
        kid,
        purpose,
        secrets.token_bytes(32),
        state,
    )


def test_one_pre_published_next_key_per_purpose(admin: Conn) -> None:
    with admin.tx(rollback=True):
        _key(admin, "int1-next-1", "next")
        with pytest.raises(asyncpg.UniqueViolationError):
            _key(admin, "int1-next-2", "next")


def _doc(kid: str, sequence: int) -> str:
    body = {
        "sequence": sequence,
        "issued_at": "2026-10-11T00:00:00.000Z",
        "keys": [],
        "next_key": None,
    }
    return json.dumps({"kid": kid, "alg": "Ed25519", "sig": "x" * 86, "body": body})


def _issue(conn: Conn, kid: str, sequence: int, document: str) -> None:
    conn.execute(
        "INSERT INTO sibyl.signing_key_set (purpose, sequence, signer_kid, active_kid, document,"
        " body_sha256, issued_at) VALUES ('agent_token', $1, $2, $2, $3, $4, now())",
        sequence,
        kid,
        document,
        b"\x01" * 32,
    )


def test_key_set_history_is_append_only(admin: Conn, roles: dict[str, Conn]) -> None:
    kid = "int1-ks-" + secrets.token_hex(3)
    _key(admin, kid, "retired")
    app = roles["sibyl_app"]
    with app.tx():
        _issue(app, kid, 1, _doc(kid, 1))
    with app.tx(rollback=True), pytest.raises(asyncpg.UniqueViolationError):
        _issue(app, kid, 1, _doc(kid, 1))
    for statement in (
        "UPDATE sibyl.signing_key_set SET document = document WHERE signer_kid = $1",
        "DELETE FROM sibyl.signing_key_set WHERE signer_kid = $1",
    ):
        with admin.tx(rollback=True), pytest.raises(asyncpg.PostgresError):
            admin.execute(statement, kid)
    with roles["sibyl_ingest"].tx(rollback=True), pytest.raises(asyncpg.InsufficientPrivilegeError):
        _issue(roles["sibyl_ingest"], kid, 2, _doc(kid, 2))


@pytest.mark.parametrize("mutation", ["signer_mismatch", "sequence_mismatch", "not_json_object"])
def test_key_set_document_is_bound_to_its_row(admin: Conn, mutation: str) -> None:
    kid = "int1-kb-" + secrets.token_hex(3)
    _key(admin, kid, "retired")
    document = {
        "signer_mismatch": _doc("someone-else", 1),
        "sequence_mismatch": _doc(kid, 7),
        "not_json_object": "[1, 2, 3]",
    }[mutation]
    with admin.tx(rollback=True), pytest.raises(asyncpg.PostgresError):
        _issue(admin, kid, 1, document)


# --- credential probe: job-bound read of the sealed secret (B14) --------------------------------


def test_worker_reads_a_sealed_secret_only_for_a_probe_job_it_holds(
    fx: TenantFixture, roles: dict[str, Conn], admin: Conn
) -> None:
    worker = roles["sibyl_worker"]
    with admin.tx(fx.tenant_id):
        cred = admin.fetchval(
            "SELECT id FROM sibyl.provider_credential WHERE tenant_id = $1"
            " AND ciphertext IS NOT NULL"
            " LIMIT 1",
            fx.tenant_id,
        )
    assert cred is not None
    with worker.tx(fx.tenant_id, rollback=True):
        job = _enqueue(
            worker,
            fx.tenant_id,
            requested_by=None,
            requested_by_kind="system",
            subject_kind="provider_credential",
            subject_id=cred,
        )
        sealed = "SELECT * FROM sibyl.probe_credential_sealed($1)"
        assert worker.fetch(sealed, job) == []  # queued: no lease
        worker.execute(
            "UPDATE sibyl.job SET state = 'running', attempts = 1,"
            " lease_until = now() + interval '1 minute' WHERE id = $1",
            job,
        )
        rows = worker.fetch(sealed, job)
        assert [r["credential_id"] for r in rows] == [cred] and rows[0]["ciphertext"]
        worker.execute(
            "UPDATE sibyl.job SET lease_until = now() - interval '1 second' WHERE id = $1", job
        )
        assert worker.fetch(sealed, job) == []  # lease expired
    with (
        roles["sibyl_app"].tx(fx.tenant_id, rollback=True),
        pytest.raises(asyncpg.InsufficientPrivilegeError),
    ):
        roles["sibyl_app"].fetch("SELECT * FROM sibyl.probe_credential_sealed($1)", uuid.uuid4())
