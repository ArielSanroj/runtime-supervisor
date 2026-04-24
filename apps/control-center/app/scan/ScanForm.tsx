"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { recordScan } from "@/lib/repo-history";
import type { ScanResponse } from "@/lib/scans";
import FindingsList from "./FindingsList";

const POLL_INTERVAL_MS = 2000;
const POLL_MAX_ATTEMPTS = 60; // 60 * 2s = 2 minutes cap

export default function ScanForm() {
  const [url, setUrl] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [scan, setScan] = useState<ScanResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, []);

  const poll = useCallback((scanId: string, attempt: number) => {
    timerRef.current = setTimeout(async () => {
      try {
        const res = await fetch(`/api/scans/${encodeURIComponent(scanId)}`, {
          cache: "no-store",
        });
        const data = (await res.json()) as ScanResponse & { error?: string };
        if (!res.ok) {
          setError(data.error ?? `${res.status} ${res.statusText}`);
          setSubmitting(false);
          return;
        }
        setScan(data);
        if (data.status === "done") {
          if (data.github_url) {
            const highCount = (data.findings ?? []).filter((f) => f.confidence === "high").length;
            const criticalCombos = (data.combos ?? []).filter((c) => c.severity === "critical").length;
            recordScan({
              github_url: data.github_url,
              scan_id: data.scan_id,
              ran_at: data.completed_at ?? new Date().toISOString(),
              high_findings: highCount,
              critical_combos: criticalCombos,
            });
          }
          setSubmitting(false);
          return;
        }
        if (data.status === "error") {
          setSubmitting(false);
          return;
        }
        if (attempt >= POLL_MAX_ATTEMPTS) {
          setError("scan is taking longer than 2 minutes — try again or check server logs.");
          setSubmitting(false);
          return;
        }
        poll(scanId, attempt + 1);
      } catch (e) {
        setError((e as Error).message);
        setSubmitting(false);
      }
    }, POLL_INTERVAL_MS);
  }, []);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (submitting) return;
    setError(null);
    setScan(null);
    setSubmitting(true);
    try {
      const res = await fetch("/api/scans", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ github_url: url.trim() }),
      });
      const data = (await res.json()) as ScanResponse & { error?: string };
      if (!res.ok) {
        setError(data.error ?? `${res.status} ${res.statusText}`);
        setSubmitting(false);
        return;
      }
      setScan(data);
      poll(data.scan_id, 1);
    } catch (e) {
      setError((e as Error).message);
      setSubmitting(false);
    }
  };

  const status = scan?.status ?? null;
  const disabled = submitting || status === "queued" || status === "scanning";

  return (
    <div>
      <form onSubmit={onSubmit} className="flex flex-col gap-3 sm:flex-row">
        <input
          type="url"
          required
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://github.com/owner/repo"
          disabled={disabled}
          className="flex-1 rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-3 font-mono text-sm text-zinc-100 placeholder:text-zinc-600 focus:border-emerald-500/50 focus:outline-none disabled:opacity-60"
        />
        <button
          type="submit"
          disabled={disabled}
          className="rounded-lg bg-emerald-500 px-6 py-3 text-sm font-semibold text-black transition-colors hover:bg-emerald-400 disabled:cursor-not-allowed disabled:bg-zinc-800 disabled:text-zinc-500"
        >
          {disabled ? "scanning…" : "scan"}
        </button>
      </form>

      {error && (
        <div className="mt-6 rounded-lg border border-rose-900/50 bg-rose-500/10 p-4 text-sm text-rose-300">
          <div className="font-mono text-xs uppercase tracking-widest text-rose-400">error</div>
          <p className="mt-1">{error}</p>
        </div>
      )}

      {scan && (status === "queued" || status === "scanning") && (
        <StatusCard scan={scan} />
      )}

      {scan && status === "error" && (
        <div className="mt-6 rounded-lg border border-rose-900/50 bg-rose-500/10 p-4 text-sm text-rose-300">
          <div className="font-mono text-xs uppercase tracking-widest text-rose-400">scan failed</div>
          <p className="mt-1">{scan.error}</p>
          <p className="mt-2 text-xs text-zinc-500">scan_id: {scan.scan_id}</p>
        </div>
      )}

      {scan && status === "done" && <FindingsList scan={scan} />}
    </div>
  );
}

function StatusCard({ scan }: { scan: ScanResponse }) {
  const label = scan.status === "queued" ? "queued — waiting for a worker" : "scanning — cloning + running 12 detectors";
  return (
    <div className="mt-6 rounded-lg border border-zinc-800 bg-zinc-900/60 p-5">
      <div className="flex items-center gap-3">
        <span className="relative flex h-3 w-3">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
          <span className="relative inline-flex h-3 w-3 rounded-full bg-emerald-500" />
        </span>
        <span className="font-mono text-sm text-zinc-300">{label}</span>
      </div>
      <div className="mt-3 font-mono text-xs text-zinc-600">
        {scan.github_url}
        {scan.ref ? ` @ ${scan.ref}` : ""}
      </div>
    </div>
  );
}
