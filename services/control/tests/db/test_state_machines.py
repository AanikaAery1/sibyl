# ruff: noqa: S608 -- SQL identifiers here come from pg_catalog or fixed literals, never from input
"""All nine state machines are wired to a trigger and refuse every illegal update (G0-tests F4).

Routing is INSERT-driven and covered exhaustively by test_routing_apply; the other eight are
checked here by disabling every other user trigger inside a rolled-back transaction, so the
state-edge trigger alone is under test."""

from __future__ import annotations

import re

import asyncpg

from .conftest import Conn
from .fixtures import populate_tenant


def _machines(admin: Conn) -> list[tuple[str, str, str, str]]:
    out = []
    for r in admin.fetch(
        "SELECT c.relname, t.tgname, pg_get_triggerdef(t.oid) AS d FROM pg_trigger t "
        "JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_proc p ON p.oid = t.tgfoid "
        "WHERE p.proname = 'trg_state_edge' AND NOT t.tgisinternal AND NOT c.relispartition"
    ):
        m = re.search(r"trg_state_edge\('(\w+)', '(\w+)'\)", r["d"])
        assert m, r["d"]
        out.append((r["relname"], r["tgname"], m.group(1), m.group(2)))
    return out


def test_every_machine_is_wired_to_exactly_one_trigger(admin: Conn) -> None:
    wired = [m for _, _, m, _ in _machines(admin)]
    seeded = {r["machine"] for r in admin.fetch("SELECT DISTINCT machine FROM sibyl.state_edge")}
    assert sorted(wired) == sorted(seeded)


def test_every_machine_refuses_every_illegal_update(admin: Conn) -> None:
    fx = populate_tenant(admin, "machines")
    wrong: list[tuple[object, ...]] = []
    checked: set[str] = set()
    for table, trigger_name, machine, col in _machines(admin):
        if machine == "routing":
            continue
        edges = admin.fetch(
            "SELECT from_state, to_state, trigger FROM sibyl.state_edge WHERE machine = $1",
            machine,
        )
        states = {e["to_state"] for e in edges} | {
            e["from_state"] for e in edges if e["from_state"]
        }
        with admin.tx(fx.tenant_id, rollback=True):
            admin.execute(f"ALTER TABLE sibyl.{table} DISABLE TRIGGER USER")
            admin.execute(f"ALTER TABLE sibyl.{table} ENABLE TRIGGER {trigger_name}")
            admin.execute("SET LOCAL session_replication_role = origin")
            row = admin.fetchrow(
                f'SELECT ctid::text AS ctid, "{col}"::text AS s FROM sibyl.{table} '
                "WHERE tenant_id = $1 LIMIT 1",
                fx.tenant_id,
            )
            assert row is not None, f"fixture has no {table} row"
            legal = {(e["to_state"], e["trigger"]) for e in edges if e["from_state"] == row["s"]}
            attempts = [(t, "") for t in sorted(states - {row["s"]} - {t for t, _ in legal})]
            attempts += [
                (t, "zz_bogus")
                for t, trig in sorted(legal)
                if trig != "*" and t != row["s"] and (t, "*") not in legal
            ]
            for target, trig in attempts:
                admin.execute("SAVEPOINT a")
                try:
                    admin.execute("SELECT set_config('app.transition_trigger', $1, true)", trig)
                    admin.execute(
                        f'UPDATE sibyl.{table} SET "{col}" = $1 WHERE ctid = $2::text::tid',
                        target,
                        row["ctid"],
                    )
                    wrong.append((machine, row["s"], target, trig, "accepted"))
                except asyncpg.PostgresError as exc:
                    if exc.sqlstate != "SB010":
                        wrong.append(
                            (machine, row["s"], target, trig, exc.sqlstate, str(exc)[:120])
                        )
                admin.execute("ROLLBACK TO SAVEPOINT a")
                checked.add(machine)
    assert wrong == [], wrong
    assert len(checked) >= 4, checked  # machines whose fixture row has an illegal move


def test_the_edge_trigger_accepts_exactly_the_seeded_edges_from_every_state(admin: Conn) -> None:
    """Every machine, every from-state, every target and trigger: the trigger function itself,
    attached to a scratch table, against the seeded state_edge rows."""
    wrong: list[tuple[object, ...]] = []
    machines = {m for _, _, m, _ in _machines(admin)} - {"routing"}
    for machine in sorted(machines):
        edges = admin.fetch(
            "SELECT from_state, to_state, trigger FROM sibyl.state_edge WHERE machine = $1",
            machine,
        )
        states = sorted({e["to_state"] for e in edges} | {e["from_state"] for e in edges} - {""})
        triggers = sorted({e["trigger"] for e in edges} - {"*"} | {"", "zz_bogus"})
        legal = {(e["from_state"], e["to_state"], e["trigger"]) for e in edges}
        with admin.tx(rollback=True):
            admin.execute("CREATE TEMP TABLE zz_machine (s text) ON COMMIT DROP")
            admin.execute(
                "CREATE TRIGGER zz_edge BEFORE UPDATE ON zz_machine FOR EACH ROW "
                f"EXECUTE FUNCTION sibyl.trg_state_edge('{machine}', 's')"
            )
            for frm in states:
                for to in states:
                    for trig in triggers:
                        allowed = frm == to or bool({(frm, to, trig), (frm, to, "*")} & legal)
                        admin.execute("SAVEPOINT a")
                        admin.execute("TRUNCATE zz_machine")
                        admin.execute("INSERT INTO zz_machine VALUES ($1)", frm)
                        admin.execute("SELECT set_config('app.transition_trigger', $1, true)", trig)
                        try:
                            admin.execute("UPDATE zz_machine SET s = $1", to)
                            accepted = True
                        except asyncpg.PostgresError as exc:
                            accepted = False
                            if exc.sqlstate != "SB010":
                                wrong.append((machine, frm, to, trig, exc.sqlstate))
                        admin.execute("ROLLBACK TO SAVEPOINT a")
                        if accepted != allowed:
                            wrong.append(
                                (machine, frm, to, trig, "accepted" if accepted else "refused")
                            )
    assert wrong == [], wrong[:20]
