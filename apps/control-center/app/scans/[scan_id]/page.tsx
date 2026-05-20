import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import FindingsList from "@/app/scan/FindingsList";
import { buildEnglishBanner, getScan, type ScanResponse } from "@/lib/scans";
import ShareBar from "./ShareBar";

export const dynamic = "force-dynamic";
export const revalidate = 0;

type PageProps = {
  params: Promise<{ scan_id: string }>;
  searchParams: Promise<{ t?: string }>;
};

export async function generateMetadata({
  params,
  searchParams,
}: PageProps): Promise<Metadata> {
  const { scan_id } = await params;
  const { t } = await searchParams;
  let banner = "Scan results";
  try {
    const scan = await getScan(scan_id, t ?? null);
    if (scan.repo_summary) {
      banner = `Wraps for ${buildEnglishBanner(scan.repo_summary)}`;
    }
  } catch {
    // metadata best-effort — the page itself will render the error
  }
  const url = `https://www.vibefixing.me/scans/${scan_id}`;
  const description =
    "What your agent can do unchecked, ordered by blast radius. The four chokepoints to wrap, the copy-paste fix per family, and the policy that gates the side effect.";
  return {
    title: `${banner} — Vibefixing`,
    description,
    alternates: { canonical: url },
    openGraph: {
      title: banner,
      description,
      url,
      type: "article",
      siteName: "Vibefixing",
    },
    twitter: {
      card: "summary_large_image",
      title: banner,
      description,
    },
    robots: { index: false, follow: false },
  };
}

export default async function ScanResultPage({ params, searchParams }: PageProps) {
  const { scan_id } = await params;
  const { t } = await searchParams;

  let scan: ScanResponse;
  try {
    scan = await getScan(scan_id, t ?? null);
  } catch (e) {
    const err = e as Error & { status?: number };
    if (err.status === 404) notFound();
    return (
      <Layout scanId={scan_id}>
        <ErrorBlock message={err.message || "Could not load this scan."} />
      </Layout>
    );
  }

  const status = scan.status;
  const isOwner = Boolean(t);
  const isRedacted = scan.redacted === true;

  return (
    <Layout scanId={scan_id}>
      <ShareBar scanId={scan_id} accessToken={t ?? null} isOwner={isOwner} />

      {status === "queued" || status === "scanning" ? (
        <Pending scan={scan} />
      ) : status === "error" ? (
        <ErrorBlock message={scan.error ?? "Scan failed."} />
      ) : (
        <>
          {isRedacted && <RedactedNotice />}
          <div className="mt-8">
            <FindingsList scan={scan} />
          </div>
        </>
      )}
    </Layout>
  );
}

function Layout({ scanId, children }: { scanId: string; children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-black text-zinc-100 selection:bg-emerald-500/30">
      <header className="sticky top-0 z-10 border-b border-zinc-800 bg-black/70 backdrop-blur">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-4">
          <Link href="/" className="flex items-baseline gap-2 font-mono text-sm">
            <span className="text-emerald-400">$</span>
            <span className="font-semibold text-zinc-100">vibefixing</span>
            <span className="text-xs text-zinc-500">// scan {scanId.slice(0, 8)}</span>
          </Link>
          <div className="flex items-center gap-3 text-sm">
            <Link
              href="/scan"
              className="font-mono text-xs text-zinc-500 hover:text-zinc-300"
            >
              scan another
            </Link>
            <Link
              href="/"
              className="font-mono text-xs text-zinc-500 hover:text-zinc-300"
            >
              ← home
            </Link>
          </div>
        </div>
      </header>
      <section className="mx-auto max-w-4xl px-6 py-10">{children}</section>
    </div>
  );
}

function Pending({ scan }: { scan: ScanResponse }) {
  const label =
    scan.status === "queued"
      ? "queued — waiting for a worker"
      : "scanning — cloning + running detectors";
  return (
    <div className="rounded-2xl border border-zinc-800 bg-zinc-900/60 p-8">
      <div className="flex items-center gap-3">
        <span className="relative flex h-3 w-3">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
          <span className="relative inline-flex h-3 w-3 rounded-full bg-emerald-500" />
        </span>
        <span className="font-mono text-sm text-zinc-300">{label}</span>
      </div>
      {scan.github_url && (
        <div className="mt-4 font-mono text-xs text-zinc-600">
          {scan.github_url}
          {scan.ref ? ` @ ${scan.ref}` : ""}
        </div>
      )}
      <p className="mt-6 text-sm leading-7 text-zinc-400">
        Scans usually finish in 30–90 seconds. This page does not auto-refresh
        — reload when you&apos;re ready, or come back to the link later. The
        scan keeps running on our side.
      </p>
    </div>
  );
}

function ErrorBlock({ message }: { message: string }) {
  return (
    <div className="rounded-2xl border border-rose-900/50 bg-rose-500/10 p-6 text-sm text-rose-200">
      <div className="font-mono text-xs uppercase tracking-widest text-rose-400">
        scan unavailable
      </div>
      <p className="mt-2 leading-7">{message}</p>
      <Link
        href="/scan"
        className="mt-5 inline-flex rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-black hover:bg-emerald-400"
      >
        start a new scan →
      </Link>
    </div>
  );
}

function RedactedNotice() {
  return (
    <div className="mt-2 rounded-xl border border-amber-700/40 bg-amber-500/5 p-5 text-sm leading-7 text-amber-200">
      <div className="font-mono text-xs uppercase tracking-widest text-amber-400">
        public summary
      </div>
      <p className="mt-2">
        You&apos;re viewing the shareable summary. Counts and categories are
        live; file paths, line numbers, and snippets are gated.{" "}
        <Link
          href="/scan"
          className="font-medium text-amber-100 underline-offset-2 hover:underline"
        >
          Run your own scan
        </Link>{" "}
        to see the full detail, or ask the person who shared this for the
        private link.
      </p>
    </div>
  );
}
