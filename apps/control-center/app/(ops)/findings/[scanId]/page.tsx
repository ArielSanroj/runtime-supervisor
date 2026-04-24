import Link from "next/link";
import { notFound } from "next/navigation";
import FindingsList from "@/app/scan/FindingsList";
import { getScan } from "@/lib/scans";

export const dynamic = "force-dynamic";

export default async function ScanDetailPage({
  params,
}: {
  params: Promise<{ scanId: string }>;
}) {
  const { scanId } = await params;

  let scan;
  try {
    scan = await getScan(scanId);
  } catch (e) {
    const err = e as { status?: number; message?: string };
    if (err.status === 404) notFound();
    return (
      <div>
        <h1>Scan</h1>
        <div className="card" style={{ borderColor: "var(--danger)", color: "var(--danger)" }}>
          Could not load scan.
          <div className="muted mono" style={{ marginTop: 8, fontSize: 12 }}>
            {err.message ?? "unknown error"}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="row" style={{ justifyContent: "space-between", alignItems: "baseline", marginBottom: 6 }}>
        <div>
          <Link href="/findings" className="muted" style={{ fontSize: 13 }}>
            ← all scans
          </Link>
          <h1 style={{ margin: "6px 0 0 0" }}>
            <span className="mono">{scan.github_url?.replace(/^https?:\/\/github\.com\//, "").replace(/\.git\/?$/, "")}</span>
            {scan.ref && <span className="muted mono"> @{scan.ref}</span>}
          </h1>
        </div>
        <span className="muted mono" style={{ fontSize: 12 }}>
          {scan.status === "error" ? "error" : scan.completed_at ? "done" : scan.status}
        </span>
      </div>

      {scan.status === "error" && (
        <div className="card" style={{ borderColor: "var(--danger)", marginTop: 20 }}>
          <strong style={{ color: "var(--danger)" }}>Scan failed.</strong>
          <div className="muted" style={{ marginTop: 8, fontSize: 13 }}>{scan.error}</div>
        </div>
      )}

      {scan.status !== "error" && <FindingsList scan={scan} />}
    </div>
  );
}
