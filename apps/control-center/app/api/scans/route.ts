import { NextResponse } from "next/server";
import { createScan } from "@/lib/scans";

export async function POST(req: Request) {
  try {
    const body = (await req.json()) as { github_url?: string; ref?: string };
    if (!body.github_url) {
      return NextResponse.json({ error: "github_url is required" }, { status: 400 });
    }
    const scan = await createScan(body.github_url, body.ref);
    return NextResponse.json(scan, { status: 202 });
  } catch (e) {
    const err = e as Error & { status?: number };
    const status = err.status ?? 500;
    // Try to forward the upstream error body verbatim when it's JSON.
    try {
      const parsed = JSON.parse(err.message) as { detail?: string };
      return NextResponse.json({ error: parsed.detail ?? err.message }, { status });
    } catch {
      return NextResponse.json({ error: err.message }, { status });
    }
  }
}
