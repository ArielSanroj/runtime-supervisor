"""End-to-end Superloop tests (SUPERLOOP.md) over the real tables.

Cover: run produces cards, R3 labels every claim, R1 opens the review queue for
Level >= 3, ORCHESTRATE is blocked until approval, and the full loop closes with
a learning move (R8).
"""
from __future__ import annotations

DEV_TENANT = "default-dev-tenant"

VALID_LABELS = {"HECHO", "INFERENCIA", "SUPUESTO", "PREGUNTA"}


def _facade(tenant=DEV_TENANT):
    from supervisor_api.db import SessionLocal
    from supervisor_api.superloop import SuperloopFacade
    return SuperloopFacade(SessionLocal(), tenant)


def test_run_produces_cards_and_registry(seed):
    seed.seed_repo("https://github.com/acme/widgets", priority_now=3, priority_prev=3)
    sl = _facade()
    out = sl.run("all")
    assert out["count"] >= 1
    cards = [c for c in out["cards"] if c["business_card"]]
    assert cards, "expected at least one rendered business card"
    # Registro Canónico reflects classified state.
    reg = {r["producto_id"]: r for r in sl.registry()}
    assert any(r["estado_operativo"] for r in reg.values())


def test_every_claim_is_labeled_R3(seed):
    seed.seed_repo("https://github.com/acme/widgets", priority_now=3, priority_prev=1)
    out = _facade().run("repos")
    for card in out["cards"]:
        pack = card.get("evidence_pack")
        if not pack:
            continue
        for af in pack["afirmaciones"]:
            assert af["etiqueta"] in VALID_LABELS, af


def test_level3_opens_review_queue_and_blocks_orchestrate(seed):
    # Shadow review traffic + an inactive policy → "promote to enforce" = Level 3.
    seed.seed_supervisor("refund", n_review_shadow=4, with_inactive_policy=True)
    sl = _facade()
    sl.run("supervisors")

    queue = sl.cola_hitl()
    refund = [q for q in queue if q["producto_id"] == "supervisor:refund"]
    assert refund, "a Level >= 3 refund decision should be pending in the queue"
    assert refund[0]["review_item_id"], "gate must link a review item (R1)"

    # R1 — resume must NOT orchestrate a Level >= 3 decision while it's still
    # pending. The gate excludes it from the closeable set entirely.
    closed = sl.resume_aprobados()
    assert all(c["decision_id"] != refund[0]["decision_id"] for c in closed), (
        "an unapproved Level >= 3 decision must not be orchestrated (R1)")


def test_full_loop_closes_after_approval_R8(seed):
    seed.seed_supervisor("refund", n_review_shadow=4, with_inactive_policy=True)
    sl = _facade()
    sl.run("supervisors")
    refund = [q for q in sl.cola_hitl() if q["producto_id"] == "supervisor:refund"]
    decision_id = refund[0]["decision_id"]

    # Human approves via the review queue (R1).
    sl.aprobar(decision_id, aprobador="ariel@cliocircle.com", verdict="approved")

    closed = _facade().resume_aprobados()
    mine = [c for c in closed if c["decision_id"] == decision_id]
    assert mine and mine[0]["ok"] is True
    assert mine[0]["siguiente_movimiento"] in {"scale", "iterate", "hold", "kill"}

    # Next DECIDE consults the learning (R8) — ledger now has a learning row.
    learnings = _facade().ledger.ultimos_aprendizajes("supervisor:refund")
    assert learnings, "LEARN must persist a learning the next DECIDE can read"


def test_routes_run_queue_resolve(client, seed):
    seed.seed_supervisor("refund", n_review_shadow=4, with_inactive_policy=True)

    r = client.post("/v1/superloop/run", json={"scope": "supervisors"})
    assert r.status_code == 200, r.text
    assert r.json()["count"] >= 1

    q = client.get("/v1/superloop/queue").json()["queue"]
    refund = [x for x in q if x["producto_id"] == "supervisor:refund"]
    assert refund, "queue should expose the gated refund decision"
    did = refund[0]["decision_id"]

    res = client.post(
        f"/v1/superloop/decisions/{did}/resolve",
        json={"verdict": "approved", "notes": "ok"},
        headers={"X-Approver": "ariel@cliocircle.com"},
    )
    assert res.status_code == 200, res.text
    assert res.json()["estado_aprobacion"] == "aprobado"

    closed = client.post("/v1/superloop/resume").json()["closed"]
    assert any(c["decision_id"] == did and c["ok"] for c in closed)

    reg = client.get("/v1/superloop/registry").json()["products"]
    assert any(p["producto_id"] == "supervisor:refund" for p in reg)
