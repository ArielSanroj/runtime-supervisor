import { NextResponse } from "next/server";

const API = process.env.SUPERVISOR_API_URL ?? "http://localhost:8000";
const ADMIN_TOKEN = process.env.SUPERVISOR_ADMIN_TOKEN ?? "";

export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const url = new URL(request.url);
  const window = url.searchParams.get("window") ?? "7d";
  try {
    const r = await fetch(`${API}/v1/policies/${id}/replay?window=${window}`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-admin-token": ADMIN_TOKEN },
      cache: "no-store",
    });
    if (!r.ok) return NextResponse.json({ error: await r.text() }, { status: r.status });
    return NextResponse.json(await r.json());
  } catch (e) {
    return NextResponse.json({ error: (e as Error).message }, { status: 500 });
  }
}
