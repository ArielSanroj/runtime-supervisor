import { beforeEach, describe, expect, it, vi } from "vitest";
import { Client } from "@runtime-supervisor/client";
import { injectClientForTests, resetForTests } from "../src/config.js";
import { supervised } from "../src/guard.js";
import { SupervisorBlocked } from "../src/errors.js";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function buildClient(fetchImpl: typeof fetch): Client {
  return new Client({ baseUrl: "http://test", appId: "a", sharedSecret: "s", fetchImpl });
}

beforeEach(() => {
  resetForTests();
});

describe("enforcement_mode=shadow", () => {
  it("always runs wrapped fn, even when server would have denied", async () => {
    // Server reports the real decision in shadow_would_have but still
    // returns decision=allow so guards don't block.
    const fetchSpy = vi.fn(async () =>
      jsonResponse(200, {
        action_id: "a1",
        decision: "allow",
        reasons: [],
        risk_score: 0,
        policy_version: "v1",
        shadow_would_have: "deny",
      }),
    );
    injectClientForTests(buildClient(fetchSpy as unknown as typeof fetch), {
      enforcementMode: "shadow",
    });

    let ran = 0;
    const wrapped = supervised<[number], number>("refund", {
      payloadFrom: (amount) => ({ amount }),
    })(async (amount) => {
      ran += 1;
      return amount * 2;
    });

    expect(await wrapped(20000)).toBe(40000);
    expect(ran).toBe(1);

    // Verify shadow=true was sent to the server.
    const call = fetchSpy.mock.calls[0] as unknown as [string, { body?: string }];
    const body = JSON.parse(call[1].body ?? "{}");
    expect(body.shadow).toBe(true);
  });

  it("per-wrapper on_review=shadow overrides enforce mode", async () => {
    const fetchSpy = vi.fn(async () =>
      jsonResponse(200, {
        action_id: "a2",
        decision: "allow",
        reasons: [],
        risk_score: 0,
        policy_version: "v1",
        shadow_would_have: "deny",
      }),
    );
    injectClientForTests(buildClient(fetchSpy as unknown as typeof fetch), {
      enforcementMode: "enforce",
    });

    const wrapped = supervised<[number], string>("refund", {
      payloadFrom: (amount) => ({ amount }),
      onReview: "shadow",
    })(async () => "ran");

    expect(await wrapped(20000)).toBe("ran");
  });
});

describe("enforcement_mode=enforce", () => {
  it("still blocks on deny (regression)", async () => {
    const fetchSpy = vi.fn(async () =>
      jsonResponse(200, {
        action_id: "a3",
        decision: "deny",
        reasons: ["amount-exceeds-hard-cap"],
        risk_score: 0,
        policy_version: "v1",
      }),
    );
    injectClientForTests(buildClient(fetchSpy as unknown as typeof fetch), {
      enforcementMode: "enforce",
    });

    const wrapped = supervised<[number], void>("refund", {
      payloadFrom: (amount) => ({ amount }),
    })(async () => {
      throw new Error("must not run");
    });

    await expect(wrapped(20000)).rejects.toBeInstanceOf(SupervisorBlocked);

    const call = fetchSpy.mock.calls[0] as unknown as [string, { body?: string }];
    const body = JSON.parse(call[1].body ?? "{}");
    expect(body.shadow).toBe(false);
  });
});

describe("enforcement_mode=sample", () => {
  it("sample_percent=0 always shadows (never blocks)", async () => {
    const fetchSpy = vi.fn(async () =>
      jsonResponse(200, {
        action_id: "a4",
        decision: "allow",
        reasons: [],
        risk_score: 0,
        policy_version: "v1",
        shadow_would_have: "deny",
      }),
    );
    injectClientForTests(buildClient(fetchSpy as unknown as typeof fetch), {
      enforcementMode: "sample",
      samplePercent: 0,
    });

    const wrapped = supervised<[number], string>("refund", {
      payloadFrom: (amount) => ({ amount }),
    })(async () => "ran");

    for (let i = 0; i < 5; i += 1) {
      expect(await wrapped(20000)).toBe("ran");
    }
  });

  it("sample_percent=100 always enforces (blocks on deny)", async () => {
    const fetchSpy = vi.fn(async () =>
      jsonResponse(200, {
        action_id: "a5",
        decision: "deny",
        reasons: ["amount-exceeds-hard-cap"],
        risk_score: 0,
        policy_version: "v1",
      }),
    );
    injectClientForTests(buildClient(fetchSpy as unknown as typeof fetch), {
      enforcementMode: "sample",
      samplePercent: 100,
    });

    const wrapped = supervised<[number], void>("refund", {
      payloadFrom: (amount) => ({ amount }),
    })(async () => {
      throw new Error("must not run");
    });

    await expect(wrapped(20000)).rejects.toBeInstanceOf(SupervisorBlocked);
  });
});
