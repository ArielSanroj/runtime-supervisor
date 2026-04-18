"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

export default function IntegrationActions({ id, active }: { id: string; active: boolean }) {
  const router = useRouter();
  const [busy, setBusy] = useState<null | "rotate" | "revoke">(null);
  const [err, setErr] = useState<string | null>(null);
  const [newSecret, setNewSecret] = useState<string | null>(null);

  async function rotate() {
    if (!confirm("Rotate shared secret? The old secret stops working immediately.")) return;
    setBusy("rotate");
    setErr(null);
    try {
      const r = await fetch(`/api/integrations/${id}/rotate`, { method: "POST" });
      if (!r.ok) throw new Error(`${r.status}: ${await r.text()}`);
      const out = await r.json();
      setNewSecret(out.shared_secret);
      router.refresh();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  async function revoke() {
    if (!confirm("Revoke this integration? JWTs signed with its secret will immediately fail.")) return;
    setBusy("revoke");
    setErr(null);
    try {
      const r = await fetch(`/api/integrations/${id}/revoke`, { method: "POST" });
      if (!r.ok) throw new Error(`${r.status}: ${await r.text()}`);
      router.refresh();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  return (
    <div>
      <div className="row" style={{ gap: 10, flexWrap: "wrap" }}>
        <button onClick={rotate} disabled={busy !== null || !active}>
          {busy === "rotate" ? "Rotating…" : "Rotate secret"}
        </button>
        <button className="danger" onClick={revoke} disabled={busy !== null || !active}>
          {busy === "revoke" ? "Revoking…" : "Revoke"}
        </button>
      </div>
      {newSecret && (
        <div className="card" style={{ marginTop: 12, borderColor: "var(--warn)" }}>
          <strong>New secret — copy it now, shown only once:</strong>
          <input readOnly value={newSecret} onFocus={(e) => e.target.select()} style={{ marginTop: 8, fontFamily: "var(--mono)", fontSize: 13 }} />
          <button
            className="primary"
            style={{ marginTop: 10 }}
            onClick={() => navigator.clipboard.writeText(newSecret)}
          >
            Copy to clipboard
          </button>
        </div>
      )}
      {err && <p className="chain-bad" style={{ marginTop: 10 }}>{err}</p>}
    </div>
  );
}
