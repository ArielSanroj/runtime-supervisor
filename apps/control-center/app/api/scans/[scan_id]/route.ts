import { NextResponse } from "next/server";
import { getScan } from "@/lib/scans";

export async function GET(
  req: Request,
  ctx: { params: Promise<{ scan_id: string }> },
) {
  const { scan_id } = await ctx.params;
  // Propagate the per-scan access token from the submitter's URL. Without
  // it the upstream API returns redacted detail (counts + categories
  // only) — that's the honeypot mitigation. Submitters keep the token
  // client-side; random visitors who paste a bare scan_id never see it.
  const url = new URL(req.url);
  const token = url.searchParams.get("access_token");
  try {
    return NextResponse.json(await getScan(scan_id, token));
  } catch (e) {
    const err = e as Error & { status?: number };
    return NextResponse.json({ error: err.message }, { status: err.status ?? 500 });
  }
}
