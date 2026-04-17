# @runtime-supervisor/client

TypeScript client for [runtime-supervisor](https://github.com/ArielSanroj/runtime-supervisor). Uses Web Crypto (`SubtleCrypto.HMAC`) for JWT signing — works in Node 20+, modern browsers, Deno, Bun.

## Install

```bash
npm i @runtime-supervisor/client      # once published
```

## Use

```ts
import { Client } from "@runtime-supervisor/client";

const sup = new Client({
  baseUrl: process.env.SUPERVISOR_URL!,
  appId: "acme-refund-agent",
  sharedSecret: process.env.SUPERVISOR_SECRET!,   // from POST /v1/integrations
  scopes: ["refund"],
});

const decision = await sup.evaluate("refund", {
  amount: 420,
  currency: "USD",
  customer_id: "c_1234",
  customer_age_days: 18,
  refund_velocity_24h: 2,
  reason: "changed_mind",
});

if (decision.decision === "allow") await executeRefund();
else if (decision.decision === "deny") notifyUser("refund policy blocked this request");
else await enqueueForReview(decision.action_id);
```

## Dry-run

```ts
const d = await sup.evaluate("refund", payload, { dryRun: true });
// d.action_id === "dry-run", nothing persisted server-side
```

## API

- `new Client({ baseUrl, appId, sharedSecret, scopes?, tokenTtlSeconds?, fetchImpl? })`
- `evaluate(action_type, payload, { dryRun? })` → `Decision`
- `listActionTypes()` → `ActionTypeSpec[]`
- `listReviews(status?)`
- `resolveReview(id, { decision, notes }, approver?)`
- `getEvidence(actionId)`
