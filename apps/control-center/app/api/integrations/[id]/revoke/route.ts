import { NextResponse } from "next/server";
import { integrationsApi } from "@/lib/integrations";

export async function POST(_r: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  try {
    return NextResponse.json(await integrationsApi.revoke(id));
  } catch (e) {
    return NextResponse.json({ error: (e as Error).message }, { status: 500 });
  }
}
