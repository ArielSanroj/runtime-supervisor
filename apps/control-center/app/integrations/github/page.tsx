import Link from "next/link";

export const dynamic = "force-dynamic";

const API = process.env.SUPERVISOR_API_URL ?? "http://localhost:8099";

type Installation = {
  installation_id: number;
  account_login: string;
  account_type: string;
  repos: string[];
  active: boolean;
  linked_to_integration: boolean;
  installed_at: string | null;
};

async function fetchInstallation(id: string): Promise<Installation | null> {
  try {
    const r = await fetch(`${API}/v1/integrations/github/installations/${id}`, {
      cache: "no-store",
    });
    if (!r.ok) return null;
    return (await r.json()) as Installation;
  } catch {
    return null;
  }
}

export default async function GithubInstallPage({
  searchParams,
}: {
  searchParams: Promise<{ installation_id?: string; action?: string }>;
}) {
  const sp = await searchParams;
  const install = sp.installation_id ? await fetchInstallation(sp.installation_id) : null;

  return (
    <div className="min-h-screen bg-black text-zinc-100">
      <div className="mx-auto max-w-2xl px-6 py-16">
        {install ? <InstalledView install={install} /> : <NotInstalledView />}
      </div>
    </div>
  );
}

function InstalledView({ install }: { install: Installation }) {
  const isAllRepos = install.repos.includes("*");
  return (
    <div>
      <div className="font-mono text-xs uppercase tracking-widest text-emerald-400">
        ✓ github app installed
      </div>
      <h1 className="mt-3 text-3xl font-bold tracking-tight">
        Vibefixing is now watching{" "}
        <span className="text-emerald-400">
          {install.account_login}
        </span>
      </h1>
      <p className="mt-3 text-zinc-400">
        From now on, every PR opened in {isAllRepos ? "your repos" : `${install.repos.length} selected repo${install.repos.length === 1 ? "" : "s"}`} gets scanned for unsafe agent call-sites. We&apos;ll comment with anything new.
      </p>

      <div className="mt-8 rounded-xl border border-zinc-800 bg-zinc-900/60 p-6">
        <div className="font-mono text-xs uppercase tracking-widest text-zinc-500">repos covered</div>
        {isAllRepos ? (
          <p className="mt-2 text-sm text-zinc-300">
            <strong className="text-zinc-100">All current and future repos</strong> for {install.account_login}.
            You can change this at{" "}
            <a
              href={`https://github.com/settings/installations/${install.installation_id}`}
              target="_blank"
              rel="noopener noreferrer"
              className="underline hover:text-zinc-100"
            >
              github.com settings
            </a>
            .
          </p>
        ) : install.repos.length > 0 ? (
          <ul className="mt-3 space-y-1">
            {install.repos.map((r) => (
              <li key={r} className="font-mono text-sm text-zinc-300">
                {r}
              </li>
            ))}
          </ul>
        ) : (
          <p className="mt-2 text-sm text-zinc-500">
            No repos yet — add some at{" "}
            <a
              href={`https://github.com/settings/installations/${install.installation_id}`}
              target="_blank"
              rel="noopener noreferrer"
              className="underline hover:text-zinc-300"
            >
              github.com settings
            </a>
            .
          </p>
        )}
      </div>

      <div className="mt-8 rounded-xl border border-zinc-800 bg-zinc-950 p-6">
        <h2 className="font-mono text-xs uppercase tracking-widest text-zinc-500">what happens now</h2>
        <ol className="mt-3 space-y-3 text-sm leading-6 text-zinc-300">
          <li>
            <span className="font-mono text-emerald-400">1.</span> Open a PR in any covered repo. Within seconds, vibefixing scans the head ref.
          </li>
          <li>
            <span className="font-mono text-emerald-400">2.</span> If the PR introduces new unsafe call-sites (unwrapped <code className="rounded bg-zinc-800 px-1 py-0.5">stripe.refunds.create</code>, <code className="rounded bg-zinc-800 px-1 py-0.5">fs.unlink</code>, etc), we post a comment with the diff.
          </li>
          <li>
            <span className="font-mono text-emerald-400">3.</span> If the PR fixes existing findings, we acknowledge that too. Clean PRs get nothing — no spam.
          </li>
        </ol>
      </div>

      <div className="mt-8 flex flex-wrap gap-3">
        <Link href="/scan" className="rounded-lg bg-emerald-500 px-5 py-2.5 text-sm font-semibold text-black hover:bg-emerald-400">
          run a scan now →
        </Link>
        <Link href="/dashboard" className="rounded-lg border border-zinc-700 px-5 py-2.5 text-sm text-zinc-200 hover:bg-zinc-900">
          open dashboard
        </Link>
      </div>

      <details className="mt-10 text-sm text-zinc-500">
        <summary className="cursor-pointer">manage this install</summary>
        <div className="mt-3 space-y-2 pl-4">
          <p>
            Add/remove repos:{" "}
            <a
              href={`https://github.com/settings/installations/${install.installation_id}`}
              target="_blank"
              rel="noopener noreferrer"
              className="underline hover:text-zinc-300"
            >
              github.com/settings/installations/{install.installation_id}
            </a>
          </p>
          <p>installation id: <code className="rounded bg-zinc-900 px-1.5 py-0.5">{install.installation_id}</code></p>
          <p>installed at: <code className="rounded bg-zinc-900 px-1.5 py-0.5">{install.installed_at}</code></p>
          <p>active: {install.active ? "yes" : "no"}</p>
        </div>
      </details>
    </div>
  );
}

function NotInstalledView() {
  return (
    <div>
      <div className="font-mono text-xs uppercase tracking-widest text-zinc-500">github integration</div>
      <h1 className="mt-3 text-3xl font-bold tracking-tight">Watch every PR for new unsafe actions</h1>
      <p className="mt-3 text-zinc-400">
        Install the Vibefixing GitHub App on your repo. We&apos;ll scan every PR for new unwrapped call-sites — refunds, DB writes, shell exec, agent chokepoints — and comment before merge.
      </p>

      <div className="mt-8 rounded-xl border border-amber-900/40 bg-amber-500/5 p-6">
        <div className="font-mono text-xs uppercase tracking-widest text-amber-400">setup required</div>
        <p className="mt-2 text-sm text-zinc-300">
          The App isn&apos;t registered yet. See{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5">docs/github-app-setup.md</code> in the repo for steps.
          Once registered + env vars set, this page receives the install callback and shows your covered repos.
        </p>
      </div>

      <div className="mt-8">
        <Link href="/scan" className="rounded-lg bg-emerald-500 px-5 py-2.5 text-sm font-semibold text-black hover:bg-emerald-400">
          ← run a manual scan instead
        </Link>
      </div>
    </div>
  );
}
