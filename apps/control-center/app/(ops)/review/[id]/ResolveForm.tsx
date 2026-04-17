"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

const API = process.env.NEXT_PUBLIC_SUPERVISOR_API_URL ?? "http://localhost:8000";

export default function ResolveForm({ id }: { id: string }) {
  const router = useRouter();
  const [notes, setNotes] = useState("");
  const [approver, setApprover] = useState("ariel@cliocircle.com");
  const [busy, setBusy] = useState<null | "approved" | "rejected">(null);
  const [err, setErr] = useState<string | null>(null);

  async function resolve(decision: "approved" | "rejected") {
    setBusy(decision);
    setErr(null);
    try {
      const res = await fetch(`${API}/v1/review-cases/${id}/resolve`, {
        method: "POST",
        headers: { "content-type": "application/json", "X-Approver": approver },
        body: JSON.stringify({ decision, notes: notes || undefined }),
      });
      if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
      router.refresh();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="grid" style={{ gap: 10 }}>
      <label>
        <span className="muted">Approver</span>
        <input value={approver} onChange={(e) => setApprover(e.target.value)} />
      </label>
      <label>
        <span className="muted">Notes (optional)</span>
        <textarea value={notes} onChange={(e) => setNotes(e.target.value)} />
      </label>
      <div className="row" style={{ gap: 10 }}>
        <button
          className="primary"
          disabled={busy !== null}
          onClick={() => resolve("approved")}
        >
          {busy === "approved" ? "Approving…" : "Approve"}
        </button>
        <button
          className="danger"
          disabled={busy !== null}
          onClick={() => resolve("rejected")}
        >
          {busy === "rejected" ? "Rejecting…" : "Reject"}
        </button>
      </div>
      {err && <p className="chain-bad">{err}</p>}
    </div>
  );
}
