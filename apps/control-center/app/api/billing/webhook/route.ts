import { NextResponse } from "next/server";

// Stripe webhook proxy. Stripe validates the request via the
// Stripe-Signature header against the raw request body — we MUST forward the
// body byte-for-byte (no JSON.parse round-trip) and pass the signature along.

const API = process.env.SUPERVISOR_API_URL ?? "http://localhost:8000";

export async function POST(request: Request) {
  const sig = request.headers.get("stripe-signature");
  if (!sig) {
    return NextResponse.json({ detail: "missing Stripe-Signature header" }, { status: 400 });
  }
  const raw = await request.text();
  try {
    const r = await fetch(`${API}/v1/billing/webhook/stripe`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "stripe-signature": sig,
      },
      body: raw,
    });
    const data = await r.json().catch(() => ({}));
    return NextResponse.json(data, { status: r.status });
  } catch (e) {
    return NextResponse.json({ detail: (e as Error).message }, { status: 502 });
  }
}
