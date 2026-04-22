import { NextResponse } from "next/server";
import { tenantsApi } from "@/lib/tenants";

export async function GET() {
  try {
    return NextResponse.json(await tenantsApi.list());
  } catch (e) {
    return NextResponse.json({ error: (e as Error).message }, { status: 500 });
  }
}
