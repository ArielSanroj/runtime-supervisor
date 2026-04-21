"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";

interface Props {
  intervalMs: number;
  enabled?: boolean;
}

/**
 * Polls router.refresh() on an interval so the Server Component's data
 * stays fresh without the operator having to reload. Paused when the tab
 * is hidden (visibilitychange) so background tabs don't hammer the API.
 */
export function AutoRefresh({ intervalMs, enabled = true }: Props) {
  const router = useRouter();

  useEffect(() => {
    if (!enabled) return;

    let timer: ReturnType<typeof setInterval> | null = null;

    const start = () => {
      if (timer !== null) return;
      timer = setInterval(() => {
        router.refresh();
      }, intervalMs);
    };
    const stop = () => {
      if (timer === null) return;
      clearInterval(timer);
      timer = null;
    };

    const onVisibility = () => {
      if (document.visibilityState === "hidden") stop();
      else start();
    };

    if (document.visibilityState !== "hidden") start();
    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      stop();
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [router, intervalMs, enabled]);

  return null;
}
