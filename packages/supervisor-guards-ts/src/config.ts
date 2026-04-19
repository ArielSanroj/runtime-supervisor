import { Client } from "@runtime-supervisor/client";

export type OnReview = "block" | "fail_closed" | "fail_open";

export interface GuardsConfig {
  baseUrl?: string;
  appId?: string;
  sharedSecret?: string;
  scopes?: string[];
  defaultOnReview?: OnReview;
  reviewPollIntervalMs?: number;
  reviewTimeoutMs?: number;
}

let _client: Client | null = null;
let _defaultOnReview: OnReview = "block";
let _pollIntervalMs = 2000;
let _timeoutMs = 60000;

export function configure(cfg: GuardsConfig = {}): void {
  _client = new Client({
    baseUrl: cfg.baseUrl ?? process.env.SUPERVISOR_BASE_URL ?? "http://localhost:8000",
    appId: cfg.appId ?? process.env.SUPERVISOR_APP_ID ?? "",
    sharedSecret: cfg.sharedSecret ?? process.env.SUPERVISOR_SECRET ?? "",
    scopes: cfg.scopes ?? (process.env.SUPERVISOR_SCOPES ?? "*").split(",").filter(Boolean),
  });
  if (cfg.defaultOnReview) _defaultOnReview = cfg.defaultOnReview;
  if (cfg.reviewPollIntervalMs) _pollIntervalMs = cfg.reviewPollIntervalMs;
  if (cfg.reviewTimeoutMs) _timeoutMs = cfg.reviewTimeoutMs;
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

// Test hooks
export function injectClientForTests(client: Client): void {
  _client = client;
}

export function resetForTests(): void {
  _client = null;
  _defaultOnReview = "block";
  _pollIntervalMs = 2000;
  _timeoutMs = 60000;
}
