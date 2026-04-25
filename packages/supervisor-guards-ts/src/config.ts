import { randomUUID } from "node:crypto";
import { Client } from "@runtime-supervisor/client";

export type OnReview = "block" | "fail_closed" | "fail_open" | "shadow";
export type EnforcementMode = "shadow" | "sample" | "enforce";

export interface GuardsConfig {
  baseUrl?: string;
  appId?: string;
  sharedSecret?: string;
  scopes?: string[];
  defaultOnReview?: OnReview;
  reviewPollIntervalMs?: number;
  reviewTimeoutMs?: number;
  enforcementMode?: EnforcementMode;
  samplePercent?: number;
  /**
   * Anonymous shadow attribution. When `appId`/`sharedSecret` are not
   * provided, the SDK falls back to anonymous shadow mode and tags every
   * evaluate request with this id so the user can later claim the
   * events with an email signup at vibefixing.me.
   *
   * Default: SUPERVISOR_CLIENT_ID env var, or a freshly-generated UUID
   * scoped to this process.
   */
  clientId?: string;
}

const DEFAULT_PUBLIC_BASE_URL = "https://vibefixing.ngrok.app";

let _client: Client | null = null;
let _defaultOnReview: OnReview = "block";
let _pollIntervalMs = 2000;
let _timeoutMs = 60000;
let _enforcementMode: EnforcementMode = "shadow";
let _samplePercent = 10;
let _appId = "";

function envMode(): EnforcementMode | undefined {
  const v = process.env.SUPERVISOR_ENFORCEMENT_MODE;
  return v === "shadow" || v === "sample" || v === "enforce" ? v : undefined;
}

export function configure(cfg: GuardsConfig = {}): void {
  const resolvedAppId = cfg.appId ?? process.env.SUPERVISOR_APP_ID ?? "";
  const resolvedSecret = cfg.sharedSecret ?? process.env.SUPERVISOR_SECRET ?? "";
  const isAnonymous = !resolvedAppId || !resolvedSecret;

  // Pick a public default when running unauthenticated so the SDK's
  // zero-config form (`configure()` with no args + no env) actually
  // reaches a live supervisor instead of localhost. Authenticated
  // installs are expected to set their own baseUrl.
  const fallbackBaseUrl = isAnonymous ? DEFAULT_PUBLIC_BASE_URL : "http://localhost:8000";

  // Anonymous mode requires a stable client_id so prior shadow events
  // can be claimed later. Prefer explicit config / env, otherwise mint
  // one for the lifetime of the process.
  const resolvedClientId = isAnonymous
    ? cfg.clientId ?? process.env.SUPERVISOR_CLIENT_ID ?? randomUUID()
    : undefined;

  _client = new Client({
    baseUrl: cfg.baseUrl ?? process.env.SUPERVISOR_BASE_URL ?? fallbackBaseUrl,
    appId: resolvedAppId,
    sharedSecret: resolvedSecret,
    scopes: cfg.scopes ?? (process.env.SUPERVISOR_SCOPES ?? "*").split(",").filter(Boolean),
    clientId: resolvedClientId,
  });
  _appId = resolvedAppId;
  if (cfg.defaultOnReview) _defaultOnReview = cfg.defaultOnReview;
  if (cfg.reviewPollIntervalMs) _pollIntervalMs = cfg.reviewPollIntervalMs;
  if (cfg.reviewTimeoutMs) _timeoutMs = cfg.reviewTimeoutMs;
  // Anonymous installs are pinned to shadow regardless of ENFORCEMENT_MODE
  // — server rejects non-shadow anonymous calls anyway, but flagging this
  // here makes the failure mode easier to debug from the SDK side.
  _enforcementMode = isAnonymous ? "shadow" : (cfg.enforcementMode ?? envMode() ?? "shadow");
  const rawPct = cfg.samplePercent ?? Number(process.env.SUPERVISOR_SAMPLE_PERCENT ?? 10);
  _samplePercent = Number.isFinite(rawPct) ? Math.max(0, Math.min(100, Math.trunc(rawPct))) : 10;
}

/** Anonymous mode = no appId or no sharedSecret configured. SDK uses
 * the public anonymous shadow endpoint with a client_id tag. */
export function isAnonymousMode(): boolean {
  return _appId === "";
}

export function getResolvedClientId(): string | undefined {
  // Internal: surfaces the client_id the SDK is sending so the caller
  // can show it to the user (e.g. so they can claim it later).
  if (_client === null) return undefined;
  return _client.getClientId();
}

export function getClient(): Client {
  if (_client === null) configure();
  return _client!;
}

export function getDefaultOnReview(): OnReview {
  return _defaultOnReview;
}

export function getPollIntervalMs(): number {
  return _pollIntervalMs;
}

export function getTimeoutMs(): number {
  return _timeoutMs;
}

export function getEnforcementMode(): EnforcementMode {
  return _enforcementMode;
}

export function getSamplePercent(): number {
  return _samplePercent;
}

export function getAppId(): string {
  return _appId;
}

// Test hooks
export function injectClientForTests(
  client: Client,
  overrides: Partial<{
    enforcementMode: EnforcementMode;
    samplePercent: number;
    defaultOnReview: OnReview;
    appId: string;
  }> = {},
): void {
  _client = client;
  _enforcementMode = overrides.enforcementMode ?? "enforce";
  _samplePercent = overrides.samplePercent ?? 10;
  _defaultOnReview = overrides.defaultOnReview ?? "block";
  _appId = overrides.appId ?? "test-app";
}

export function resetForTests(): void {
  _client = null;
  _defaultOnReview = "block";
  _pollIntervalMs = 2000;
  _timeoutMs = 60000;
  _enforcementMode = "shadow";
  _samplePercent = 10;
  _appId = "";
}
