import { NextResponse } from "next/server";
import { getRepoByUrl } from "@/lib/repos";

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const github_url = searchParams.get("github_url");
  if (!github_url) {
    return NextResponse.json({ error: "github_url is required" }, { status: 400 });
  }
  try {
    const overview = await getRepoByUrl(github_url);
    return NextResponse.json(overview);
  } catch (e) {
    const err = e as Error & { status?: number };
    const status = err.status ?? 500;
    try {
      const parsed = JSON.parse(err.message) as { detail?: string };
      return NextResponse.json({ error: parsed.detail ?? err.message }, { status });
    } catch {
      return NextResponse.json({ error: err.message }, { status });
    }
  }
}
