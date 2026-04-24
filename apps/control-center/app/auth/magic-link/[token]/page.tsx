import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import Link from "next/link";

const API = process.env.SUPERVISOR_API_URL ?? "http://localhost:8000";
const COOKIE_NAME = "aic_session";

export const dynamic = "force-dynamic";

type ExchangeResponse = {
  token: string;
  user: {
    id: string;
    email: string;
    role: string;
    tenant_id: string | null;
    active: boolean;
    created_at: string;
  };
};

async function consume(token: string): Promise<{ ok: true; payload: ExchangeResponse } | { ok: false; status: number; detail: string }> {
  try {
    const r = await fetch(`${API}/v1/auth/magic-link/${encodeURIComponent(token)}`, {
      cache: "no-store",
    });
    if (!r.ok) {
      const body = await r.json().catch(() => ({ detail: r.statusText }));
      return { ok: false, status: r.status, detail: body.detail ?? r.statusText };
    }
    const payload = (await r.json()) as ExchangeResponse;
    return { ok: true, payload };
  } catch (e) {
    return { ok: false, status: 502, detail: (e as Error).message };
  }
}

export default async function MagicLinkPage({
  params,
}: {
  params: Promise<{ token: string }>;
}) {
  const { token } = await params;
  const result = await consume(token);

  if (!result.ok) {
    return (
      <div className="mx-auto flex min-h-screen max-w-xl flex-col items-center justify-center px-6 py-16 text-center">
        <div className="font-mono text-xs uppercase tracking-widest text-rose-400">link unavailable</div>
        <h1 className="mt-3 text-3xl font-semibold text-zinc-100">
          {result.status === 410 ? "This link expired or was already used." : "We couldn't sign you in."}
        </h1>
        <p className="mt-3 text-zinc-400">{result.detail}</p>
        <Link
          href="/scan"
          className="mt-8 rounded-lg border border-zinc-800 bg-zinc-900 px-5 py-2.5 text-sm font-semibold text-zinc-200 hover:bg-zinc-800"
        >
          ← back to scan
        </Link>
      </div>
    );
  }

  // Mirror the structure /api/auth/login uses so getSession() decodes both.
  const session = { token: result.payload.token, user: result.payload.user };
  const store = await cookies();
  store.set(COOKIE_NAME, btoa(JSON.stringify(session)), {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 * 8,
    secure: process.env.NODE_ENV === "production",
  });

  redirect("/dashboard");
}
