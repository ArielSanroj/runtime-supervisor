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
}

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
  _client = new Client({
    baseUrl: cfg.baseUrl ?? process.env.SUPERVISOR_BASE_URL ?? "http://localhost:8000",
    appId: resolvedAppId,
    sharedSecret: cfg.sharedSecret ?? process.env.SUPERVISOR_SECRET ?? "",
    scopes: cfg.scopes ?? (process.env.SUPERVISOR_SCOPES ?? "*").split(",").filter(Boolean),
  });
  _appId = resolvedAppId;
  if (cfg.defaultOnReview) _defaultOnReview = cfg.defaultOnReview;
  if (cfg.reviewPollIntervalMs) _pollIntervalMs = cfg.reviewPollIntervalMs;
  if (cfg.reviewTimeoutMs) _timeoutMs = cfg.reviewTimeoutMs;
  _enforcementMode = cfg.enforcementMode ?? envMode() ?? "shadow";
  const rawPct = cfg.samplePercent ?? Number(process.env.SUPERVISOR_SAMPLE_PERCENT ?? 10);
  _samplePercent = Number.isFinite(rawPct) ? Math.max(0, Math.min(100, Math.trunc(rawPct))) : 10;
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
