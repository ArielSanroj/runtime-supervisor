"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

const TEMPLATE = `name: my-policy.name
version: 1
rules:
  - id: hard-cap
    when: "payload['amount'] > 10000"
    action: deny
    reason: amount-exceeds-hard-cap
  - id: negative-amount
    when: "payload['amount'] <= 0"
    action: deny
    reason: invalid-amount
`;

const SAMPLE_PAYLOADS: Record<string, string> = {
  refund: JSON.stringify(
    { amount: 50, currency: "USD", customer_id: "c_test", customer_age_days: 400, refund_velocity_24h: 0, reason: "defective" },
    null,
    2,
  ),
  payment: JSON.stringify(
    { amount: 500, currency: "USD", vendor_id: "v_test", vendor_first_seen_days: 400, approval_chain: ["cfo"], bank_account_changed: false, beneficiary_country: "US" },
    null,
    2,
  ),
};

export default function NewPolicyForm() {
  const router = useRouter();
  const [actionType, setActionType] = useState("refund");
  const [yamlSource, setYamlSource] = useState(TEMPLATE);
  const [testPayload, setTestPayload] = useState(SAMPLE_PAYLOADS.refund);
  const [testResult, setTestResult] = useState<null | {
    decision: "allow" | "deny" | "review";
    reasons: string[];
    hits: Array<{ rule_id: string; action: string; reason: string }>;
  }>(null);
  const [busy, setBusy] = useState<null | "save-draft" | "save-promote" | "test">(null);
  const [err, setErr] = useState<string | null>(null);

  function switchActionType(next: string) {
    setActionType(next);
    if (SAMPLE_PAYLOADS[next]) setTestPayload(SAMPLE_PAYLOADS[next]);
  }

  async function save(promote: boolean) {
    setBusy(promote ? "save-promote" : "save-draft");
    setErr(null);
    try {
      const r = await fetch("/api/policies", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action_type: actionType, yaml_source: yamlSource, promote }),
      });
      if (!r.ok) throw new Error(`${r.status}: ${await r.text()}`);
      const p = await r.json();
      router.push(`/policies/${p.id}`);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  async function runTest() {
    setBusy("test");
    setErr(null);
    setTestResult(null);
    try {
      // Two-step: create a draft, test it, then delete? No — the test endpoint is on a stored policy.
      // Instead, save as draft first (without promote), then test it, then user can promote from detail page.
      const payload = JSON.parse(testPayload);
      const r = await fetch("/api/policies", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action_type: actionType, yaml_source: yamlSource, promote: false }),
      });
      if (!r.ok) throw new Error(`${r.status}: ${await r.text()}`);
      const policy = await r.json();

      const t = await fetch(`/api/policies/${policy.id}/test`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ payload }),
      });
      if (!t.ok) throw new Error(`${t.status}: ${await t.text()}`);
      setTestResult(await t.json());
      // Navigate to the draft so the user can promote or discard.
      router.push(`/policies/${policy.id}?tested=1`);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="grid cols-2">
      <div className="card">
        <h2>Source</h2>
        <label>
          <span className="muted">action_type</span>
          <select value={actionType} onChange={(e) => switchActionType(e.target.value)}>
            <option value="refund">refund</option>
            <option value="payment">payment</option>
            <option value="account_change">account_change (planned)</option>
            <option value="data_access">data_access (planned)</option>
          </select>
        </label>
        <label style={{ marginTop: 12, display: "block" }}>
          <span className="muted">YAML</span>
          <textarea
            value={yamlSource}
            onChange={(e) => setYamlSource(e.target.value)}
            spellCheck={false}
            style={{ minHeight: 320, fontFamily: "var(--mono)", fontSize: 13 }}
          />
        </label>
        <div className="row" style={{ marginTop: 12, gap: 10, flexWrap: "wrap" }}>
          <button className="primary" onClick={() => save(true)} disabled={busy !== null}>
            {busy === "save-promote" ? "Saving…" : "Save & promote"}
          </button>
          <button onClick={() => save(false)} disabled={busy !== null}>
            {busy === "save-draft" ? "Saving…" : "Save as draft"}
          </button>
        </div>
        {err && <p className="chain-bad" style={{ marginTop: 12, whiteSpace: "pre-wrap" }}>{err}</p>}
      </div>

      <div className="card">
        <h2>Test against payload</h2>
        <p className="muted" style={{ marginBottom: 8 }}>
          Test runs server-side against a <em>saved draft</em> of this policy; after a successful test you land
          on the policy detail where you can promote or deactivate.
        </p>
        <textarea
          value={testPayload}
          onChange={(e) => setTestPayload(e.target.value)}
          spellCheck={false}
          style={{ minHeight: 200, fontFamily: "var(--mono)", fontSize: 13 }}
        />
        <div className="row" style={{ marginTop: 12 }}>
          <button onClick={runTest} disabled={busy !== null}>
            {busy === "test" ? "Testing…" : "Save draft & test"}
          </button>
        </div>
        {testResult && (
          <div style={{ marginTop: 12 }}>
            <p>
              Decision:{" "}
              <span className={`badge ${testResult.decision === "allow" ? "approved" : testResult.decision === "deny" ? "rejected" : "pending"}`}>
                {testResult.decision}
              </span>
            </p>
            {testResult.reasons.length > 0 && (
              <>
                <h3 className="muted" style={{ fontSize: 12, textTransform: "uppercase", letterSpacing: "0.08em" }}>Reasons</h3>
                <ul className="mono">{testResult.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
