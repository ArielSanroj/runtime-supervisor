import { NextRequest, NextResponse } from "next/server";

// Tier gating is currently OFF — anyone can browse /(ops)/* freely.
//
// The paywall logic is preserved below (commented) and the matcher stays
// in place so we can flip it back on with a one-line change once Stripe
// goes live and we want to enforce free-vs-builder access. While billing
// secrets are still being set up, an active gate would lock the owner
// out of their own dashboard preview.
//
// Trust note (when re-enabled): the cookie value is base64(JSON({token,user}))
// — not signed at the cookie layer. The integrity-bearing artifact is the
// HS256 token inside, validated by the supervisor on every API call. The
// UI gate is best-effort UX; the backend is the security boundary.

// const COOKIE_NAME = "aic_session";
//
// type CookieSession = {
//   user?: { role?: string; tier?: string };
// };
//
// function readSession(req: NextRequest): CookieSession | null {
//   const raw = req.cookies.get(COOKIE_NAME)?.value;
//   if (!raw) return null;
//   try {
//     return JSON.parse(atob(raw)) as CookieSession;
//   } catch {
//     return null;
//   }
// }
//
// function bounceToUpsell(req: NextRequest): NextResponse {
//   const url = req.nextUrl.clone();
//   url.pathname = "/scan";
//   url.search = "?upgrade=required";
//   return NextResponse.redirect(url);
// }

export function middleware(_req: NextRequest) {
  // Pass-through. Re-enable the readSession + bounceToUpsell flow above
  // when Stripe is live and we want to gate Builder access.
  return NextResponse.next();
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
