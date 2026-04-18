"use client";

import { useState } from "react";

type Delivery = {
  id: number;
  subscription_id: string;
  event_type: string;
  status_code: number | null;
  error: string | null;
  attempts: number;
  delivered_at: string | null;
  created_at: string;
};

export default function DeliveriesPanel({ integrationId, subId }: { integrationId: string; subId: string }) {
  const [rows, setRows] = useState<Delivery[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function load() {
    setBusy(true);
    setErr(null);
    try {
      const r = await fetch(`/api/integrations/${integrationId}/webhooks/${subId}/deliveries`);
      if (!r.ok) throw new Error(`${r.status}: ${await r.text()}`);
      setRows(await r.json());
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ marginTop: 12 }}>
      <button onClick={load} disabled={busy}>{busy ? "Loading…" : "Show recent deliveries"}</button>
      {err && <p className="chain-bad" style={{ marginTop: 8 }}>{err}</p>}
      {rows && (rows.length === 0 ? (
        <p className="muted" style={{ marginTop: 8 }}>No deliveries yet for this subscription.</p>
      ) : (
        <div className="card" style={{ padding: 0, marginTop: 8 }}>
          <table>
            <thead>
              <tr><th>When</th><th>Event</th><th>HTTP</th><th>Attempts</th><th>Result</th></tr>
            </thead>
            <tbody>
              {rows.map((d) => (
                <tr key={d.id}>
                  <td className="muted mono">{new Date(d.created_at).toLocaleString()}</td>
                  <td className="mono">{d.event_type}</td>
                  <td className="mono">{d.status_code ?? "—"}</td>
                  <td className="mono">{d.attempts}</td>
                  <td>
                    {d.delivered_at ? (
                      <span className="badge approved">delivered</span>
                    ) : d.error ? (
                      <span className="badge rejected">failed</span>
                    ) : (
                      <span className="badge pending">pending</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
    </div>
  );
}
