"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

const KNOWN_ACTION_TYPES = ["refund", "payment", "account_change", "data_access", "tool_use", "compliance"];

type TenantOption = { id: string; name: string };

export default function NewIntegrationForm() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<string[]>(["*"]);
  const [tenantId, setTenantId] = useState<string>("");
  const [tenants, setTenants] = useState<TenantOption[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [created, setCreated] = useState<{ id: string; name: string; shared_secret: string } | null>(null);

  // Fetch tenants once so the operator can assign the new integration
  // explicitly. Empty-string "" means "let the server pick the default".
  useEffect(() => {
    fetch("/api/tenants")
      .then((r) => (r.ok ? r.json() : []))
      .then((rows: TenantOption[]) => setTenants(Array.isArray(rows) ? rows : []))
      .catch(() => setTenants([]));
  }, []);

  function toggleScope(s: string) {
    setScopes((cur) => {
      if (s === "*") return ["*"];
      const without = cur.filter((x) => x !== "*");
      return without.includes(s) ? without.filter((x) => x !== s) : [...without, s];
    });
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const body: Record<string, unknown> = {
        name,
        scopes: scopes.length ? scopes : ["*"],
      };
      if (tenantId) body.tenant_id = tenantId;
      const r = await fetch("/api/integrations", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!r.ok) throw new Error(`${r.status}: ${await r.text()}`);
      const out = await r.json();
      setCreated({ id: out.id, name: out.name, shared_secret: out.shared_secret });
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (created) {
    return (
      <div className="card" style={{ borderColor: "var(--warn)" }}>
        <h2>Integration created — copy the secret now</h2>
        <p className="muted">
          This is the only time you'll see <code>shared_secret</code>. Store it in your agent's environment.
        </p>
        <label style={{ marginTop: 12, display: "block" }}>
          <span className="muted">SUPERVISOR_APP_ID</span>
          <input readOnly value={created.id} style={{ fontFamily: "var(--mono)", fontSize: 13 }} onFocus={(e) => e.target.select()} />
        </label>
        <label style={{ marginTop: 8, display: "block" }}>
          <span className="muted">SUPERVISOR_SECRET</span>
          <input readOnly value={created.shared_secret} style={{ fontFamily: "var(--mono)", fontSize: 13 }} onFocus={(e) => e.target.select()} />
        </label>
        <div className="row" style={{ marginTop: 16, gap: 10 }}>
          <button
            className="primary"
            onClick={() => {
              navigator.clipboard.writeText(`SUPERVISOR_APP_ID=${created.id}\nSUPERVISOR_SECRET=${created.shared_secret}\n`);
            }}
          >
            Copy env block
          </button>
          <Link href={`/integrations/${created.id}`} className="badge approved" style={{ padding: "8px 14px" }}>
            Configure integration →
          </Link>
        </div>
      </div>
    );
  }

  return (
    <form onSubmit={submit} className="card" style={{ maxWidth: 640 }}>
      <label style={{ display: "block", marginBottom: 12 }}>
        <span className="muted">Name</span>
        <input value={name} onChange={(e) => setName(e.target.value)} required placeholder="e.g. acme-refund-agent" />
      </label>

      <label style={{ display: "block", marginBottom: 12 }}>
        <span className="muted">Tenant</span>
        <select
          value={tenantId}
          onChange={(e) => setTenantId(e.target.value)}
          style={{ width: "100%", padding: "8px 10px", background: "var(--panel-2)", color: "var(--text)", border: "1px solid var(--border)", borderRadius: 8, marginTop: 6 }}
        >
          <option value="">— default (server fallback) —</option>
          {tenants.map((t) => (
            <option key={t.id} value={t.id}>
              {t.name}
            </option>
          ))}
        </select>
      </label>

      <label style={{ display: "block", marginBottom: 12 }}>
        <span className="muted">Scopes</span>
        <div className="row" style={{ flexWrap: "wrap", gap: 6, marginTop: 6 }}>
          <label className={`badge ${scopes.includes("*") ? "approved" : ""}`} style={{ cursor: "pointer" }}>
            <input
              type="checkbox"
              checked={scopes.includes("*")}
              onChange={() => toggleScope("*")}
              style={{ marginRight: 6 }}
            />
            * (all)
          </label>
          {KNOWN_ACTION_TYPES.map((s) => (
            <label key={s} className={`badge ${scopes.includes(s) ? "approved" : ""}`} style={{ cursor: "pointer" }}>
              <input
                type="checkbox"
                checked={scopes.includes(s)}
                disabled={scopes.includes("*")}
                onChange={() => toggleScope(s)}
                style={{ marginRight: 6 }}
              />
              {s}
            </label>
          ))}
        </div>
      </label>

      <div className="row" style={{ gap: 10 }}>
        <button className="primary" type="submit" disabled={busy || !name}>
          {busy ? "Creating…" : "Create integration"}
        </button>
        <Link href="/integrations" className="muted">cancel</Link>
      </div>
      {err && <p className="chain-bad" style={{ marginTop: 12 }}>{err}</p>}
    </form>
  );
}
