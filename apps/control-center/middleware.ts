import { NextResponse } from "next/server";

// Auth desactivada para simplificar el modo local de pruebas. El backend
// sigue protegido por JWT HS256 (REQUIRE_AUTH=true), y el UI firma sus
// requests server-side con SUPERVISOR_APP_ID + SUPERVISOR_SECRET — no
// hace falta sesión humana para ver el panel.
export function middleware() {
  return NextResponse.next();
}

export const config = {
  matcher: ["/dashboard/:path*", "/review/:path*", "/threats/:path*", "/policies/:path*", "/integrations/:path*"],
};
