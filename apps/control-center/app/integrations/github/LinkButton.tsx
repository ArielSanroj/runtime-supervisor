"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

type State =
  | { kind: "idle" }
  | { kind: "submitting" }
  | { kind: "linked" }
  | { kind: "error"; message: string };

export default function LinkButton({
  installationId,
  email,
}: {
  installationId: number;
  email: string;
}) {
  const [state, setState] = useState<State>({ kind: "idle" });
  const router = useRouter();

  async function onClick() {
    setState({ kind: "submitting" });
    try {
      const r = await fetch(
        `/api/integrations/github/installations/${installationId}/link`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({}),
        },
      );
      if (r.ok) {
        setState({ kind: "linked" });
        // Force re-render of the parent server component so the
        // PairingStrip flips to the linked state on next paint.
        router.refresh();
      } else {
        const body = await r.json().catch(() => ({}));
        setState({ kind: "error", message: body.error ?? body.detail ?? `HTTP ${r.status}` });
      }
    } catch (e) {
      setState({ kind: "error", message: String(e) });
    }
  }

  if (state.kind === "linked") {
    return (
      <span className="inline-flex items-center gap-2 rounded-md border border-emerald-700/40 bg-emerald-500/10 px-3 py-2 font-mono text-sm text-emerald-300">
        ✓ paired to {email}
      </span>
    );
  }

  return (
    <div className="flex flex-wrap items-center gap-3">
      <button
        type="button"
        onClick={onClick}
        disabled={state.kind === "submitting"}
        className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-black hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-50"
      >
        {state.kind === "submitting" ? "pairing…" : `pair to ${email}`}
      </button>
      {state.kind === "error" && (
        <span className="text-sm text-rose-400">{state.message}</span>
      )}
    </div>
  );
}
