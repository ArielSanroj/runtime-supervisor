import { NextResponse } from "next/server";
import { integrationsApi } from "@/lib/integrations";

export async function PUT(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  try {
    const body = await request.json();
    return NextResponse.json(await integrationsApi.setExecuteConfig(id, body));
  } catch (e) {
    return NextResponse.json({ error: (e as Error).message }, { status: 500 });
  }
}
