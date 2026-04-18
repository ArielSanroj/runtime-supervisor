import { NextRequest, NextResponse } from "next/server";

const COOKIE_NAME = "aic_session";
const OPS_PREFIXES = ["/dashboard", "/review", "/threats", "/policies", "/integrations"];

const ROLE_ACCESS: Record<string, string[]> = {
  "/dashboard": ["admin", "compliance", "ops", "auditor"],
  "/review": ["admin", "compliance", "ops"],
  "/threats": ["admin", "compliance", "ops", "auditor"],
  "/policies": ["admin", "compliance"],
  "/integrations": ["admin", "ops"],
};

function findRoleGate(path: string): string[] | null {
  for (const prefix of Object.keys(ROLE_ACCESS)) {
    if (path === prefix || path.startsWith(prefix + "/")) return ROLE_ACCESS[prefix];
  }
  return null;
}

export function middleware(req: NextRequest) {
  const path = req.nextUrl.pathname;

  // Only gate the ops routes; landing and API routes pass through.
  const needsAuth = OPS_PREFIXES.some((p) => path === p || path.startsWith(p + "/"));
  if (!needsAuth) return NextResponse.next();

  const raw = req.cookies.get(COOKIE_NAME)?.value;
  if (!raw) {
    const url = req.nextUrl.clone();
    url.pathname = "/login";
    url.searchParams.set("next", path);
    return NextResponse.redirect(url);
  }

  try {
    const session = JSON.parse(atob(raw));
    const allowed = findRoleGate(path);
    if (allowed && !allowed.includes(session.user.role)) {
      const url = req.nextUrl.clone();
      url.pathname = "/dashboard";
      return NextResponse.redirect(url);
    }
  } catch {
    const url = req.nextUrl.clone();
    url.pathname = "/login";
    return NextResponse.redirect(url);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/dashboard/:path*", "/review/:path*", "/threats/:path*", "/policies/:path*", "/integrations/:path*"],
};
