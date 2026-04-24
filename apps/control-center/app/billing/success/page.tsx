import Link from "next/link";

export const dynamic = "force-dynamic";

export default async function BillingSuccess({
  searchParams,
}: {
  searchParams: Promise<{ session_id?: string; canceled?: string }>;
}) {
  const sp = await searchParams;
  const canceled = sp.canceled === "true";

  if (canceled) {
    return (
      <div className="mx-auto flex min-h-screen max-w-xl flex-col items-center justify-center px-6 py-16 text-center">
        <div className="font-mono text-xs uppercase tracking-widest text-amber-400">checkout canceled</div>
        <h1 className="mt-3 text-3xl font-semibold text-zinc-100">No problem.</h1>
        <p className="mt-3 text-zinc-400">
          You stepped out of Stripe before paying. No charge was made.
        </p>
        <Link
          href="/scan"
          className="mt-8 rounded-lg border border-zinc-800 bg-zinc-900 px-5 py-2.5 text-sm font-semibold text-zinc-200 hover:bg-zinc-800"
        >
          ← back to scan
        </Link>
      </div>
    );
  }

  return (
    <div className="mx-auto flex min-h-screen max-w-xl flex-col items-center justify-center px-6 py-16 text-center">
      <div className="font-mono text-xs uppercase tracking-widest text-emerald-400">payment confirmed</div>
      <h1 className="mt-3 text-3xl font-semibold text-zinc-100">Check your email.</h1>
      <p className="mt-4 text-zinc-300">
        We just emailed you a one-click sign-in link. Open it from any device to enter your dashboard.
      </p>
      <p className="mt-3 text-sm text-zinc-500">
        Didn&apos;t arrive in 60 seconds? Check spam, or{" "}
        <Link href="/auth/magic-link/send" className="text-emerald-400 underline-offset-2 hover:underline">
          re-send it
        </Link>
        .
      </p>
      <div className="mt-10 rounded-xl border border-zinc-800 bg-zinc-900/40 p-5 text-left text-sm text-zinc-400">
        <div className="font-mono text-xs uppercase tracking-widest text-zinc-500">what happens next</div>
        <ol className="mt-3 list-decimal space-y-2 pl-5">
          <li>Open the email and click the link (valid 15 minutes).</li>
          <li>You land on the dashboard. No password to remember.</li>
          <li>Re-scan your repos as often as you want — history is now saved.</li>
        </ol>
      </div>
    </div>
  );
}
