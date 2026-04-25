"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

type State =
  | { kind: "idle" }
  | { kind: "running"; scanId: string; elapsed: number }
  | { kind: "done"; scanId: string }
  | { kind: "error"; message: string };

export default function RescanButton({ githubUrl }: { githubUrl: string }) {
  const [state, setState] = useState<State>({ kind: "idle" });
  const router = useRouter();

  async function start() {
    setState({ kind: "running", scanId: "", elapsed: 0 });
    try {
      const r = await fetch("/v1/scans", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ github_url: githubUrl }),
      });
      if (!r.ok) {
        const body = await r.json().catch(() => ({}));
        setState({ kind: "error", message: body.detail ?? `Error ${r.status}` });
        return;
      }
      const { scan_id } = (await r.json()) as { scan_id: string };
      const t0 = Date.now();
      setState({ kind: "running", scanId: scan_id, elapsed: 0 });
      poll(scan_id, t0);
    } catch (e) {
      setState({ kind: "error", message: String(e) });
    }
  }

  async function poll(scanId: string, t0: number) {
    const tick = async () => {
      try {
        const r = await fetch(`/v1/scans/${scanId}`, { cache: "no-store" });
        if (!r.ok) {
          setTimeout(tick, 1500);
          return;
        }
        const data = (await r.json()) as { status: string };
        if (data.status === "done") {
          setState({ kind: "done", scanId });
          // Hard refresh so layout + history pull fresh data.
          router.refresh();
          setTimeout(() => setState({ kind: "idle" }), 4000);
          return;
        }
        if (data.status === "error") {
          setState({ kind: "error", message: "Scan failed — check logs" });
          return;
        }
        setState({
          kind: "running",
          scanId,
          elapsed: Math.floor((Date.now() - t0) / 1000),
        });
        setTimeout(tick, 1500);
      } catch {
        setTimeout(tick, 2000);
      }
    };
    tick();
  }

  if (state.kind === "running") {
    return (
      <button
        type="button"
        disabled
        className="button-secondary"
        title="Scanning the latest commit — usually 10–30s"
      >
        scanning… {state.elapsed}s
      </button>
    );
  }

  if (state.kind === "done") {
    return (
      <button type="button" disabled className="button-secondary" style={{ color: "#34d399" }}>
        ✓ scan complete
      </button>
    );
  }

  if (state.kind === "error") {
    return (
      <button
        type="button"
        onClick={start}
        className="button-secondary"
        style={{ color: "#fb7185" }}
        title={state.message}
      >
        retry rescan
      </button>
    );
  }

  return (
    <button type="button" onClick={start} className="button-secondary">
      rescan
    </button>
  );
}
