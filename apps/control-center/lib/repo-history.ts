/**
 * Client-side repo history kept in localStorage.
 *
 * There's no auth/tenant model yet, so the dashboard can't ask the backend
 * "which repos has this user scanned?". Instead the browser keeps the list
 * locally and hydrates the dashboard by fanning out to `/v1/repos/by-url`.
 *
 * When auth lands we migrate: read this list once, POST it as seed to the
 * authenticated endpoint, drop the localStorage layer.
 */
const KEY = "vibefixing.scan.history";
const MAX_ENTRIES = 25;

export type RepoHistoryEntry = {
  github_url: string;
  scan_id: string;
  ran_at: string; // ISO
  high_findings?: number;
  critical_combos?: number;
};

function safeParse(raw: string | null): RepoHistoryEntry[] {
  if (!raw) return [];
  try {
    const data = JSON.parse(raw);
    if (!Array.isArray(data)) return [];
    return data.filter(
      (e): e is RepoHistoryEntry =>
        typeof e?.github_url === "string" && typeof e?.scan_id === "string" && typeof e?.ran_at === "string",
    );
  } catch {
    return [];
  }
}

export function getHistory(): RepoHistoryEntry[] {
  if (typeof window === "undefined") return [];
  return safeParse(window.localStorage.getItem(KEY));
}

/**
 * Record a completed scan. Keeps one entry per github_url (latest wins),
 * newest first, capped at MAX_ENTRIES.
 */
export function recordScan(entry: RepoHistoryEntry): RepoHistoryEntry[] {
  if (typeof window === "undefined") return [];
  const current = getHistory().filter((e) => e.github_url !== entry.github_url);
  const next = [entry, ...current].slice(0, MAX_ENTRIES);
  window.localStorage.setItem(KEY, JSON.stringify(next));
  return next;
}

export function forgetRepo(github_url: string): RepoHistoryEntry[] {
  if (typeof window === "undefined") return [];
  const next = getHistory().filter((e) => e.github_url !== github_url);
  window.localStorage.setItem(KEY, JSON.stringify(next));
  return next;
}
