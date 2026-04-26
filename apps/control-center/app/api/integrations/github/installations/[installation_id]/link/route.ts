import { NextResponse } from "next/server";
import { getSession } from "@/lib/session";
import { buildToken } from "@runtime-supervisor/client";

const API = process.env.SUPERVISOR_API_URL ?? "http://localhost:8099";
const APP_ID = process.env.SUPERVISOR_APP_ID;
const SECRET = process.env.SUPERVISOR_SECRET;

/** POST /api/integrations/github/installations/{id}/link
 *
 * Server-side BFF: pulls the user's tenant_id + email out of the session
 * cookie and signs the upstream call with the admin integration token
 * (same trust model as every other dashboard write). The browser never
 * sees credentials and the user can't ask for someone else's tenant.
 */
export async function POST(
  _request: Request,
  { params }: { params: Promise<{ installation_id: string }> },
): Promise<NextResponse> {
  const { installation_id } = await params;

  const session = await getSession();
  if (!session) {
    return NextResponse.json({ error: "not signed in" }, { status: 401 });
  }
  const tenantId = session.user.tenant_id;
  if (!tenantId) {
    return NextResponse.json(
      { error: "your account has no tenant — contact support" },
      { status: 400 },
    );
  }

  const headers: Record<string, string> = { "content-type": "application/json" };
  if (APP_ID && SECRET) {
    const token = await buildToken(APP_ID, ["*"], SECRET, 300);
    headers.authorization = `Bearer ${token}`;
  }

  const r = await fetch(
    `${API}/v1/integrations/github/installations/${encodeURIComponent(installation_id)}/link`,
    {
      method: "POST",
      headers,
      body: JSON.stringify({
        tenant_id: tenantId,
        linked_by_email: session.user.email,
      }),
      cache: "no-store",
    },
  );

  const body = await r.text();
  return new NextResponse(body, {
    status: r.status,
    headers: { "content-type": r.headers.get("content-type") ?? "application/json" },
  });
}
