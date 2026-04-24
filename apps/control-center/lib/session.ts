import { cookies } from "next/headers";

const COOKIE_NAME = "aic_session";

export type Tier = "free" | "builder";

export type Session = {
  token: string;
  user: {
    id: string;
    email: string;
    role: "admin" | "compliance" | "ops" | "auditor";
    tenant_id: string | null;
    tier?: Tier;
    stripe_subscription_status?: string | null;
  };
};

export async function getSession(): Promise<Session | null> {
  const store = await cookies();
  const raw = store.get(COOKIE_NAME);
  if (!raw) return null;
  try {
    return JSON.parse(atob(raw.value)) as Session;
  } catch {
    return null;
  }
}

export async function setSession(s: Session): Promise<void> {
  const store = await cookies();
  store.set(COOKIE_NAME, btoa(JSON.stringify(s)), {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 * 8, // 8h
    secure: process.env.NODE_ENV === "production",
  });
}

export async function clearSession(): Promise<void> {
  const store = await cookies();
  store.delete(COOKIE_NAME);
}

/** Role → route permissions. `null` means no access. */
export const ROUTE_ACCESS: Record<string, ("admin" | "compliance" | "ops" | "auditor")[]> = {
  "/dashboard": ["admin", "compliance", "ops", "auditor"],
  "/review": ["admin", "compliance", "ops"],
  "/threats": ["admin", "compliance", "ops", "auditor"],
  "/policies": ["admin", "compliance"],
  "/integrations": ["admin", "ops"],
};

export function canAccess(role: Session["user"]["role"], path: string): boolean {
  for (const [prefix, roles] of Object.entries(ROUTE_ACCESS)) {
    if (path === prefix || path.startsWith(prefix + "/")) {
      return roles.includes(role);
    }
  }
  // Unknown ops routes default-deny; non-ops routes (/, /login) are open.
  return path === "/" || path === "/login" || !path.startsWith("/dashboard") && !path.startsWith("/review")
    && !path.startsWith("/threats") && !path.startsWith("/policies") && !path.startsWith("/integrations");
}
