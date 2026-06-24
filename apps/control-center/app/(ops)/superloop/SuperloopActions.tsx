"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

const API = process.env.NEXT_PUBLIC_SUPERVISOR_API_URL ?? "http://localhost:8000";

const HEADERS = {
  "content-type": "application/json",
  "ngrok-skip-browser-warning": "true",
} as const;

type Scope = "all" | "repos" | "supervisors";

export function RunControls() {
  const router = useRouter();
  const [scope, setScope] = useState<Scope>("all");
  const [busy, setBusy] = useState<null | "run" | "resume">(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function post(path: string, body?: unknown, label?: string) {
    try {
      const res = await fetch(`${API}${path}`, {
        method: "POST",
        headers: HEADERS,
        body: body ? JSON.stringify(body) : undefined,
      });
      if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
      const data = await res.json();
      setMsg(label ?? "Done");
      router.refresh();
      return data;
    } catch (e) {
      setErr((e as Error).message);
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-3 font-mono text-sm">
      <select
        value={scope}
        onChange={(e) => setScope(e.target.value as Scope)}
        className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-zinc-200"
      >
        <option value="all">all units</option>
        <option value="repos">repos</option>
        <option value="supervisors">supervisors</option>
      </select>
      <button
        disabled={busy !== null}
        onClick={async () => {
          setBusy("run");
          setErr(null);
          setMsg(null);
          const d = await post("/v1/superloop/run", { scope }, "Loop ran");
          if (d) setMsg(`Loop ran over ${d.count} unit(s).`);
          setBusy(null);
        }}
        className="rounded bg-emerald-500 px-3 py-1 font-semibold text-black hover:bg-emerald-400 disabled:opacity-50"
      >
        {busy === "run" ? "Running…" : "Run loop"}
      </button>
      <button
        disabled={busy !== null}
        onClick={async () => {
          setBusy("resume");
          setErr(null);
          setMsg(null);
          const d = await post("/v1/superloop/resume", undefined, "Resumed");
          if (d) setMsg(`Closed ${d.closed?.length ?? 0} approved decision(s).`);
          setBusy(null);
        }}
        title="ORCHESTRATE → VERIFY → LEARN over approved (and Level<3) decisions"
        className="rounded border border-zinc-700 px-3 py-1 text-zinc-200 hover:border-emerald-500 disabled:opacity-50"
      >
        {busy === "resume" ? "Resuming…" : "Resume approved"}
      </button>
      {msg && <span className="text-emerald-400">{msg}</span>}
      {err && <span className="text-red-400">{err}</span>}
    </div>
  );
}

export function ResolveButtons({ decisionId, approver }: { decisionId: string; approver: string }) {
  const router = useRouter();
  const [busy, setBusy] = useState<null | string>(null);
  const [err, setErr] = useState<string | null>(null);

  async function resolve(verdict: "approved" | "rejected" | "requires_changes") {
    setBusy(verdict);
    setErr(null);
    try {
      const res = await fetch(`${API}/v1/superloop/decisions/${decisionId}/resolve`, {
        method: "POST",
        headers: { ...HEADERS, "X-Approver": approver || "anonymous" },
        body: JSON.stringify({ verdict }),
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
    <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
      <button
        disabled={busy !== null}
        onClick={() => resolve("approved")}
        className="rounded bg-emerald-500 px-2.5 py-1 font-semibold text-black hover:bg-emerald-400 disabled:opacity-50"
      >
        {busy === "approved" ? "Approving…" : "Approve"}
      </button>
      <button
        disabled={busy !== null}
        onClick={() => resolve("rejected")}
        className="rounded border border-red-700 px-2.5 py-1 text-red-300 hover:bg-red-950 disabled:opacity-50"
      >
        {busy === "rejected" ? "Rejecting…" : "Reject"}
      </button>
      <button
        disabled={busy !== null}
        onClick={() => resolve("requires_changes")}
        className="rounded border border-zinc-700 px-2.5 py-1 text-zinc-300 hover:border-zinc-500 disabled:opacity-50"
      >
        Request changes
      </button>
      {err && <span className="text-red-400">{err}</span>}
    </div>
  );
}
