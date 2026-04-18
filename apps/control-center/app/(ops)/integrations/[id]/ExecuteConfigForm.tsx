"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

type Method = "POST" | "PUT" | "PATCH";

export default function ExecuteConfigForm({
  id,
  initialUrl,
  initialMethod,
}: {
  id: string;
  initialUrl: string;
  initialMethod: string;
}) {
  const router = useRouter();
  const [url, setUrl] = useState(initialUrl);
  const [method, setMethod] = useState<Method>(initialMethod as Method);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [ok, setOk] = useState(false);

  async function save(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    setOk(false);
    try {
      const r = await fetch(`/api/integrations/${id}/execute-config`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url: url || null, method }),
      });
      if (!r.ok) throw new Error(`${r.status}: ${await r.text()}`);
      setOk(true);
      router.refresh();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={save}>
      <label style={{ display: "block", marginBottom: 10 }}>
        <span className="muted">URL (http:// or https://, leave empty to disable)</span>
        <input
          type="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://your-app.example.com/execute"
          style={{ fontFamily: "var(--mono)", fontSize: 13 }}
        />
      </label>
      <label style={{ display: "block", marginBottom: 12 }}>
        <span className="muted">HTTP method</span>
        <select value={method} onChange={(e) => setMethod(e.target.value as Method)}>
          <option>POST</option>
          <option>PUT</option>
          <option>PATCH</option>
        </select>
      </label>
      <div className="row" style={{ gap: 10 }}>
        <button className="primary" type="submit" disabled={busy}>
          {busy ? "Saving…" : "Save"}
        </button>
        {ok && <span className="chain-ok">Saved.</span>}
      </div>
      {err && <p className="chain-bad" style={{ marginTop: 10 }}>{err}</p>}
    </form>
  );
}
