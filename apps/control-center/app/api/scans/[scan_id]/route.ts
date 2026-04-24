import { NextResponse } from "next/server";
import { getScan } from "@/lib/scans";

export async function GET(
  _req: Request,
  ctx: { params: Promise<{ scan_id: string }> },
) {
  const { scan_id } = await ctx.params;
  try {
    return NextResponse.json(await getScan(scan_id));
  } catch (e) {
    const err = e as Error & { status?: number };
    return NextResponse.json({ error: err.message }, { status: err.status ?? 500 });
  }
}
