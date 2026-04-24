import { NextRequest, NextResponse } from "next/server";

// Tier gating for /(ops)/* routes. Anyone without a session — or whose
// session reports a non-builder tier (and isn't admin) — is bounced to
// /scan?upgrade=required so they see the value (free scan) before the
// paywall.
//
// Why we trust the cookie here: the cookie value is base64(JSON({token,user}))
// — not signed at the cookie layer. The integrity-bearing artifact is the
// HS256 token inside, validated by the supervisor on every API call. The UI
// gate is best-effort UX; the backend is the security boundary.

const COOKIE_NAME = "aic_session";

type CookieSession = {
  user?: {
    role?: string;
    tier?: string;
  };
};

function readSession(req: NextRequest): CookieSession | null {
  const raw = req.cookies.get(COOKIE_NAME)?.value;
  if (!raw) return null;
  try {
    return JSON.parse(atob(raw)) as CookieSession;
  } catch {
    return null;
  }
}

function bounceToUpsell(req: NextRequest): NextResponse {
  const url = req.nextUrl.clone();
  url.pathname = "/scan";
  url.search = "?upgrade=required";
  return NextResponse.redirect(url);
}

export function middleware(req: NextRequest) {
  const session = readSession(req);
  const role = session?.user?.role;
  const tier = session?.user?.tier;

  // Admin bypasses tier gate (internal staff).
  if (role === "admin") return NextResponse.next();
  // Builder tier passes.
  if (tier === "builder") return NextResponse.next();
  // Everyone else (no session, free tier) gets redirected.
  return bounceToUpsell(req);
}

export const config = {
  matcher: [
    "/dashboard/:path*",
    "/review/:path*",
    "/threats/:path*",
    "/findings/:path*",
    "/policies/:path*",
    "/integrations/:path*",
  ],
};
