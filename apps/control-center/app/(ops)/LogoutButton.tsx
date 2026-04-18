"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

export default function LogoutButton() {
  const router = useRouter();
  const [busy, setBusy] = useState(false);

  async function logout() {
    setBusy(true);
    await fetch("/api/auth/logout", { method: "POST" });
    router.push("/login");
    router.refresh();
  }

  return (
    <button
      onClick={logout}
      disabled={busy}
      style={{ marginLeft: 8, fontSize: 13, padding: "4px 10px" }}
    >
      {busy ? "…" : "Sign out"}
    </button>
  );
}
