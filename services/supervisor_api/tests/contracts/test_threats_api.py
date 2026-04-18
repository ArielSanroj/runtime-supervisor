"""Contract tests for /v1/threats/* and the simulator."""
from __future__ import annotations


def test_threat_catalog_lists_five_entries(client):
    r = client.get("/v1/threats/catalog")
    assert r.status_code == 200
    catalog = r.json()
    ids = {t["id"] for t in catalog}
    assert {"prompt-injection", "jailbreak", "hallucination", "pii-exfil", "unbounded-consumption"}.issubset(ids)
    for entry in catalog:
        assert set(entry.keys()) == {"id", "title", "owasp_ref", "one_liner", "severity", "remediation", "sample_attack"}
        assert entry["owasp_ref"].startswith("LLM")


def test_simulate_prompt_injection_blocks(client):
    r = client.post("/v1/simulate/attack?type=prompt-injection")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["threat_id"] == "prompt-injection"
    assert data["decision"]["decision"] == "deny"
    assert data["decision"]["threat_level"] == "critical"
    assert any(s["detector_id"] == "prompt-injection" for s in data["threats"])


def test_simulate_jailbreak_blocks(client):
    data = client.post("/v1/simulate/attack?type=jailbreak").json()
    assert data["decision"]["decision"] == "deny"
    assert any(s["detector_id"] == "jailbreak" for s in data["threats"])


def test_simulate_hallucination_reviews(client):
    data = client.post("/v1/simulate/attack?type=hallucination").json()
    # Hallucination signals are warn → review
    assert data["decision"]["threat_level"] == "warn"
    assert data["decision"]["decision"] == "review"


def test_simulate_pii_exfil_reviews(client):
    data = client.post("/v1/simulate/attack?type=pii-exfil").json()
    assert data["decision"]["threat_level"] == "warn"
    assert data["decision"]["decision"] == "review"


def test_simulate_velocity_blocks(client):
    data = client.post("/v1/simulate/attack?type=unbounded-consumption").json()
    # The sample attack has refund_velocity_24h=99 which trips the simulator marker → critical
    assert data["decision"]["threat_level"] == "critical"
    assert data["decision"]["decision"] == "deny"


def test_simulate_unknown_type_is_404(client):
    r = client.post("/v1/simulate/attack?type=not-a-real-threat")
    assert r.status_code == 404


def test_decision_out_includes_threat_fields(client):
    r = client.post("/v1/actions/evaluate", json={
        "action_type": "refund",
        "payload": {"amount": 50, "currency": "USD", "customer_id": "c1",
                    "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective"},
    })
    body = r.json()
    assert "threat_level" in body
    assert "threats" in body
