import { NextResponse } from "next/server";
import { integrationsApi } from "@/lib/integrations";

export async function DELETE(
  _r: Request,
  { params }: { params: Promise<{ id: string; subId: string }> },
) {
  const { id, subId } = await params;
  try {
    await integrationsApi.deleteWebhook(id, subId);
    return new NextResponse(null, { status: 204 });
  } catch (e) {
    return NextResponse.json({ error: (e as Error).message }, { status: 500 });
  }
}
