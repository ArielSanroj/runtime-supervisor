"use client";

import { useCallback, useState } from "react";

type Props = {
  scanId: string;
  accessToken: string | null;
  isOwner: boolean;
};

type Tab = "public" | "private";

export default function ShareBar({ scanId, accessToken, isOwner }: Props) {
  const [tab, setTab] = useState<Tab>(isOwner ? "private" : "public");
  const [copied, setCopied] = useState<Tab | null>(null);

  const origin =
    typeof window !== "undefined" ? window.location.origin : "https://www.vibefixing.me";

  const publicUrl = `${origin}/scans/${scanId}`;
  const privateUrl = accessToken
    ? `${origin}/scans/${scanId}?t=${encodeURIComponent(accessToken)}`
    : null;

  const copy = useCallback(
    async (which: Tab) => {
      const url = which === "private" ? privateUrl : publicUrl;
      if (!url) return;
      try {
        await navigator.clipboard.writeText(url);
        setCopied(which);
        setTimeout(() => setCopied(null), 1500);
      } catch {
        // clipboard refused — surface as a benign tooltip flicker (no-op)
      }
    },
    [privateUrl, publicUrl],
  );

  const activeUrl = tab === "private" ? privateUrl : publicUrl;
  const showPrivate = isOwner && privateUrl;

  return (
    <div className="rounded-2xl border border-zinc-800 bg-zinc-950/60 p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="font-mono text-xs uppercase tracking-widest text-emerald-400">
            share this scan
          </div>
          <p className="mt-1 text-sm text-zinc-400">
            {showPrivate
              ? "Two links — pick what fits the audience."
              : "Send this link to anyone — counts and categories are visible, file paths and snippets are gated."}
          </p>
        </div>
        {showPrivate && (
          <div className="inline-flex rounded-lg border border-zinc-800 bg-zinc-900 p-1 text-xs font-mono">
            <button
              type="button"
              onClick={() => setTab("public")}
              className={
                tab === "public"
                  ? "rounded-md bg-emerald-500/20 px-3 py-1.5 text-emerald-200"
                  : "rounded-md px-3 py-1.5 text-zinc-500 hover:text-zinc-300"
              }
            >
              public
            </button>
            <button
              type="button"
              onClick={() => setTab("private")}
              className={
                tab === "private"
                  ? "rounded-md bg-emerald-500/20 px-3 py-1.5 text-emerald-200"
                  : "rounded-md px-3 py-1.5 text-zinc-500 hover:text-zinc-300"
              }
            >
              private
            </button>
          </div>
        )}
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-3">
        <code className="flex-1 truncate rounded-lg border border-zinc-800 bg-black/40 px-3 py-2.5 font-mono text-xs text-zinc-400">
          {activeUrl}
        </code>
        <button
          type="button"
          onClick={() => copy(tab)}
          className="rounded-lg bg-emerald-500 px-4 py-2.5 text-xs font-semibold text-black hover:bg-emerald-400"
        >
          {copied === tab ? "✓ copied" : "copy link"}
        </button>
      </div>

      {showPrivate && (
        <p className="mt-3 text-xs leading-5 text-zinc-500">
          {tab === "private" ? (
            <>
              <span className="text-amber-300">private link</span> — includes
              the one-time access token. Anyone who opens it sees file paths,
              line numbers, and snippets. Share with collaborators only.
            </>
          ) : (
            <>
              <span className="text-emerald-300">public link</span> — safe to
              post on LinkedIn, X, or send to anyone. Visitors see the
              risk-ranked card layout with counts and categories; details stay
              gated.
            </>
          )}
        </p>
      )}
    </div>
  );
}
