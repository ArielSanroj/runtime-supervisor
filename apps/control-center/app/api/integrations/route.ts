import { NextResponse } from "next/server";
import { integrationsApi } from "@/lib/integrations";

export async function GET() {
  try {
    return NextResponse.json(await integrationsApi.list());
  } catch (e) {
    return NextResponse.json({ error: (e as Error).message }, { status: 500 });
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const created = await integrationsApi.create(body);
    return NextResponse.json(created, { status: 201 });
  } catch (e) {
    return NextResponse.json({ error: (e as Error).message }, { status: 500 });
  }
}
