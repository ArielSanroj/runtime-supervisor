"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

export default function LoginForm({ next }: { next: string }) {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const r = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      if (!r.ok) {
        const body = await r.json().catch(() => ({ error: r.statusText }));
        throw new Error(body.error || `${r.status}`);
      }
      router.push(next);
      router.refresh();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <label className="block">
        <span className="font-mono text-xs uppercase tracking-widest text-zinc-500">Email</span>
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          autoFocus
          autoComplete="email"
        />
      </label>
      <label className="block">
        <span className="font-mono text-xs uppercase tracking-widest text-zinc-500">Password</span>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          autoComplete="current-password"
        />
      </label>
      <button
        type="submit"
        className="primary"
        disabled={busy || !email || !password}
        style={{ width: "100%" }}
      >
        {busy ? "Signing in…" : "Sign in"}
      </button>
      {err && <p className="text-sm text-rose-400">{err}</p>}
      <p className="text-xs leading-5 text-zinc-500">
        Don&apos;t have an account? Ask your admin to create one via{" "}
        <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-zinc-400">POST /v1/users</code>.
      </p>
    </form>
  );
}
