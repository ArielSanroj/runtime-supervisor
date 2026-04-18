import { NextResponse } from "next/server";

const API = process.env.SUPERVISOR_API_URL ?? "http://localhost:8000";
const COOKIE_NAME = "aic_session";

export async function POST(request: Request) {
  const body = await request.json();
  try {
    const r = await fetch(`${API}/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      return NextResponse.json({ error: await r.text() }, { status: r.status });
    }
    const session = await r.json();
    const res = NextResponse.json({ ok: true, user: session.user });
    res.cookies.set(COOKIE_NAME, btoa(JSON.stringify(session)), {
      httpOnly: true,
      sameSite: "lax",
      path: "/",
      maxAge: 60 * 60 * 8,
      secure: process.env.NODE_ENV === "production",
    });
    return res;
  } catch (e) {
    return NextResponse.json({ error: (e as Error).message }, { status: 500 });
  }
}
