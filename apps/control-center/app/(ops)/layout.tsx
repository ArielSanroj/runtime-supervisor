import Link from "next/link";
import LogoutButton from "./LogoutButton";
import { getSession } from "@/lib/session";
import { tenantsApi } from "@/lib/tenants";

const NAV = [
  { href: "/dashboard", label: "Fix" },
  { href: "/scan", label: "Scan" },
  { href: "/findings", label: "Scans" },
  { href: "/review", label: "Reviews" },
  { href: "/threats", label: "Threats" },
  { href: "/policies", label: "Rules" },
  { href: "/integrations", label: "Integrations" },
] as const;

async function currentTenantLabel(): Promise<string | null> {
  // Session JWT carries tenant_id from login; resolve to the human name so
  // the header shows "acme" instead of a UUID. Fail soft — if the tenant
  // vanished or the admin token isn't configured, just hide the pill.
  const session = await getSession();
  if (!session?.user.tenant_id) return null;
  try {
    const t = await tenantsApi.get(session.user.tenant_id);
    return t.name;
  } catch {
    return null;
  }
}

export default async function OpsLayout({ children }: { children: React.ReactNode }) {
  const tenantName = await currentTenantLabel();

  return (
    <div className="ops-shell min-h-screen bg-black text-zinc-100">
      <header className="sticky top-0 z-10 border-b border-zinc-800 bg-black/70 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between gap-6 px-6 py-3">
          <div className="flex items-baseline gap-3">
            <Link
              href="/"
              className="flex items-baseline gap-2 font-mono text-sm hover:opacity-80"
            >
              <span className="text-emerald-400">$</span>
              <span className="font-semibold text-zinc-100">vibefixing</span>
              <span className="text-xs text-zinc-500">// runtime-supervisor</span>
            </Link>
            {tenantName && (
              <span
                className="rounded-full border border-zinc-800 bg-zinc-900 px-2.5 py-0.5 font-mono text-xs text-zinc-400"
                title="Current tenant (from session JWT)"
              >
                tenant: <span className="text-emerald-400">{tenantName}</span>
              </span>
            )}
          </div>
          <nav className="flex items-center gap-5 font-mono text-sm text-zinc-400">
            {NAV.map((l) => (
              <Link
                key={l.href}
                href={l.href}
                className="transition-colors hover:text-emerald-400"
              >
                {l.label}
              </Link>
            ))}
          </nav>
          <LogoutButton />
        </div>
      </header>
      <main className="ops-main">{children}</main>
    </div>
  );
}
