import { NextResponse } from "next/server";
import { policiesApi } from "@/lib/policies";

export async function GET(request: Request) {
  const url = new URL(request.url);
  try {
    const policies = await policiesApi.list(
      url.searchParams.get("action_type") ?? undefined,
      url.searchParams.get("active_only") === "true",
    );
    return NextResponse.json(policies);
  } catch (e) {
    return NextResponse.json({ error: (e as Error).message }, { status: 500 });
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const p = await policiesApi.create(body);
    return NextResponse.json(p, { status: 201 });
  } catch (e) {
    const msg = (e as Error).message;
    const status = /\b4\d\d\b/.exec(msg)?.[0] ?? "500";
    return NextResponse.json({ error: msg }, { status: Number(status) });
  }
}
