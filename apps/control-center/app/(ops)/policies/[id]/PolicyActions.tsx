"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

export default function PolicyActions({
  id,
  isActive,
  deactivated,
}: {
  id: string;
  isActive: boolean;
  deactivated: boolean;
}) {
  const router = useRouter();
  const [busy, setBusy] = useState<null | "promote" | "deactivate">(null);
  const [err, setErr] = useState<string | null>(null);

  async function call(path: "promote" | "deactivate") {
    setBusy(path);
    setErr(null);
    try {
      const r = await fetch(`/api/policies/${id}/${path}`, { method: "POST" });
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
        <button
          className="primary"
          disabled={isActive || busy !== null}
          onClick={() => call("promote")}
        >
          {busy === "promote" ? "Promoting…" : isActive ? "Already active" : "Promote to active"}
        </button>
        <button
          className="danger"
          disabled={!isActive || busy !== null}
          onClick={() => call("deactivate")}
        >
          {busy === "deactivate" ? "Deactivating…" : "Deactivate"}
        </button>
      </div>
      {deactivated && !isActive && (
        <p className="muted" style={{ marginTop: 8, fontSize: 13 }}>
          Fallback to <code>packages/policies/{"{action_type}"}.base.v1.yaml</code> is active.
        </p>
      )}
      {err && <p className="chain-bad" style={{ marginTop: 8 }}>{err}</p>}
    </div>
  );
}
