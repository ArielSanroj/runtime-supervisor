import { NextResponse } from "next/server";
import { getSession } from "@/lib/session";
import { buildToken } from "@runtime-supervisor/client";

const API = process.env.SUPERVISOR_API_URL ?? "http://localhost:8099";
const APP_ID = process.env.SUPERVISOR_APP_ID;
const SECRET = process.env.SUPERVISOR_SECRET;

/** POST /api/team/invite — relay the invite to the supervisor with the
 * inviter's tenant_id pulled from the session cookie. Body: { email, role }. */
export async function POST(request: Request): Promise<NextResponse> {
  const session = await getSession();
  if (!session) {
    return NextResponse.json({ error: "not signed in" }, { status: 401 });
  }
  const tenantId = session.user.tenant_id;
  if (!tenantId) {
    return NextResponse.json({ error: "your account has no tenant" }, { status: 400 });
  }

  const incoming = (await request.json().catch(() => ({}))) as { email?: string; role?: string };
  if (!incoming.email) {
    return NextResponse.json({ error: "email required" }, { status: 400 });
  }

  const headers: Record<string, string> = { "content-type": "application/json" };
  if (APP_ID && SECRET) {
    const token = await buildToken(APP_ID, ["*"], SECRET, 300);
    headers.authorization = `Bearer ${token}`;
  }

  const r = await fetch(`${API}/v1/team/invite`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      email: incoming.email,
      role: incoming.role ?? "ops",
      tenant_id: tenantId,
    }),
    cache: "no-store",
  });
  const body = await r.text();
  return new NextResponse(body, {
    status: r.status,
    headers: { "content-type": r.headers.get("content-type") ?? "application/json" },
  });
}
