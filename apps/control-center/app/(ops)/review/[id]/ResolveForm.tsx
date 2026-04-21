"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

const API = process.env.NEXT_PUBLIC_SUPERVISOR_API_URL ?? "http://localhost:8000";

type Action = "approved" | "rejected" | "escalate";

export default function ResolveForm({
  id,
  canEscalate,
  approverEmail,
}: {
  id: string;
  canEscalate: boolean;
  approverEmail: string;
}) {
  const router = useRouter();
  const [notes, setNotes] = useState("");
  // Default to the logged-in user's email. Editable in case someone resolves
  // on behalf of another reviewer — the change is captured in evidence.
  const [approver, setApprover] = useState(approverEmail || "anonymous");
  const [busy, setBusy] = useState<null | Action>(null);
  const [err, setErr] = useState<string | null>(null);

  async function submit(action: Action) {
    setBusy(action);
    setErr(null);
    try {
      let path: string;
      let body: Record<string, unknown>;
      if (action === "escalate") {
        path = `/v1/review-cases/${id}/escalate`;
        body = { notes: notes || undefined };
      } else {
        path = `/v1/review-cases/${id}/resolve`;
        body = { decision: action, notes: notes || undefined };
      }
      const res = await fetch(`${API}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", "X-Approver": approver },
        body: JSON.stringify(body),
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
      <div className="row" style={{ gap: 10, flexWrap: "wrap" }}>
        <button className="primary" disabled={busy !== null} onClick={() => submit("approved")}>
          {busy === "approved" ? "Approving…" : "Approve"}
        </button>
        <button className="danger" disabled={busy !== null} onClick={() => submit("rejected")}>
          {busy === "rejected" ? "Rejecting…" : "Reject"}
        </button>
        {canEscalate && (
          <button disabled={busy !== null} onClick={() => submit("escalate")} title="Bump priority to high and route to the compliance queue">
            {busy === "escalate" ? "Escalating…" : "Escalate to compliance"}
          </button>
        )}
      </div>
      {err && <p className="chain-bad">{err}</p>}
    </div>
  );
}
