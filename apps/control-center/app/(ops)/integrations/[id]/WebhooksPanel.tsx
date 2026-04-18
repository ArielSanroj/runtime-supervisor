"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

type WebhookSubscription = {
  id: string;
  integration_id: string;
  url: string;
  events: string[];
  active: boolean;
  created_at: string;
};

const EVENT_CHOICES = ["decision.made", "action.denied", "review.resolved", "threat.detected"] as const;
type EventChoice = (typeof EVENT_CHOICES)[number];

export default function WebhooksPanel({ id, initial }: { id: string; initial: WebhookSubscription[] }) {
  const router = useRouter();
  const [rows, setRows] = useState<WebhookSubscription[]>(initial);
  const [newUrl, setNewUrl] = useState("");
  const [events, setEvents] = useState<EventChoice[]>(["decision.made"]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  function toggleEvent(e: EventChoice) {
    setEvents((cur) => (cur.includes(e) ? cur.filter((x) => x !== e) : [...cur, e]));
  }

  async function add(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const r = await fetch(`/api/integrations/${id}/webhooks`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url: newUrl, events }),
      });
      if (!r.ok) throw new Error(`${r.status}: ${await r.text()}`);
      const sub = await r.json();
      setRows((cur) => [...cur, sub]);
      setNewUrl("");
      setEvents(["decision.made"]);
      router.refresh();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function remove(subId: string) {
    if (!confirm("Delete this webhook subscription?")) return;
    try {
      const r = await fetch(`/api/integrations/${id}/webhooks/${subId}`, { method: "DELETE" });
      if (!r.ok && r.status !== 204) throw new Error(`${r.status}: ${await r.text()}`);
      setRows((cur) => cur.filter((s) => s.id !== subId));
      router.refresh();
    } catch (e) {
      setErr((e as Error).message);
    }
  }

  return (
    <div>
      <div className="card" style={{ padding: 0, marginBottom: 16 }}>
        {rows.length === 0 ? (
          <p className="muted" style={{ padding: 16 }}>No webhooks subscribed. Add one below.</p>
        ) : (
          <table>
            <thead>
              <tr><th>URL</th><th>Events</th><th>Created</th><th></th></tr>
            </thead>
            <tbody>
              {rows.map((s) => (
                <tr key={s.id}>
                  <td className="mono" style={{ maxWidth: 420, overflow: "hidden", textOverflow: "ellipsis" }}>{s.url}</td>
                  <td className="mono">{(s.events || []).join(", ")}</td>
                  <td className="muted mono">{new Date(s.created_at).toLocaleString()}</td>
                  <td><button className="danger" onClick={() => remove(s.id)}>delete</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <form onSubmit={add} className="card">
        <h3 style={{ marginTop: 0 }}>Add subscription</h3>
        <label style={{ display: "block", marginBottom: 10 }}>
          <span className="muted">URL</span>
          <input
            type="url"
            value={newUrl}
            onChange={(e) => setNewUrl(e.target.value)}
            placeholder="https://your-app.example.com/hook"
            required
            style={{ fontFamily: "var(--mono)", fontSize: 13 }}
          />
        </label>
        <div style={{ marginBottom: 12 }}>
          <span className="muted" style={{ fontSize: 13 }}>Events</span>
          <div className="row" style={{ flexWrap: "wrap", gap: 6, marginTop: 6 }}>
            {EVENT_CHOICES.map((e) => (
              <label key={e} className={`badge ${events.includes(e) ? "approved" : ""}`} style={{ cursor: "pointer" }}>
                <input
                  type="checkbox"
                  checked={events.includes(e)}
                  onChange={() => toggleEvent(e)}
                  style={{ marginRight: 6 }}
                />
                {e}
              </label>
            ))}
          </div>
        </div>
        <button className="primary" type="submit" disabled={busy || !newUrl || events.length === 0}>
          {busy ? "Adding…" : "Add webhook"}
        </button>
        {err && <p className="chain-bad" style={{ marginTop: 10 }}>{err}</p>}
      </form>
    </div>
  );
}
