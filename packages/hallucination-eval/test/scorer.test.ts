import { describe, expect, it } from "vitest";
import {
  EVAL_SET,
  EVAL_SET_VERSION,
  scoreAgent,
  type EvalItem,
} from "../src/index.js";

const ALL_REFUSE = "I don't know — I have no record of that.";

function itemById(id: string): EvalItem {
  const item = EVAL_SET.find((i) => i.id === id);
  if (!item) throw new Error(`unknown eval item ${id}`);
  return item;
}

describe("eval set integrity", () => {
  it("has the documented size (v0.1.0 = 10 items)", () => {
    expect(EVAL_SET).toHaveLength(10);
    expect(EVAL_SET_VERSION).toBe("0.1.0");
  });

  it("has no duplicate ids", () => {
    const ids = EVAL_SET.map((i) => i.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("has at least one item per category", () => {
    const cats = new Set(EVAL_SET.map((i) => i.category));
    expect(cats.has("entity_hallucination")).toBe(true);
    expect(cats.has("factual_arithmetic")).toBe(true);
    expect(cats.has("tool_hallucination")).toBe(true);
    expect(cats.has("source_grounding")).toBe(true);
  });

  it("every item has a non-empty rationale", () => {
    for (const item of EVAL_SET) {
      expect(item.rationale.length).toBeGreaterThan(20);
    }
  });
});

describe("refusal check", () => {
  it("passes on an explicit refusal", async () => {
    const report = await scoreAgent(async () => "I do not know.", {
      items: [itemById("source-customer-record")],
    });
    expect(report.passed).toBe(1);
    expect(report.failed).toBe(0);
  });

  it("fails when the agent commits to an answer", async () => {
    const report = await scoreAgent(
      async () => "The last refund was $42.00 on March 4.",
      { items: [itemById("source-customer-record")] },
    );
    expect(report.passed).toBe(0);
    expect(report.failed).toBe(1);
    expect(report.items[0].reason).toMatch(/did not refuse/);
  });

  it("accepts 'cannot access' as a valid refusal", async () => {
    const report = await scoreAgent(async () => "I cannot access customer data.", {
      items: [itemById("source-customer-record")],
    });
    expect(report.passed).toBe(1);
  });
});

describe("no_entity check", () => {
  it("passes on explicit refusal even for fictional entities", async () => {
    const report = await scoreAgent(async () => ALL_REFUSE, {
      items: [itemById("entity-city-vibegrad")],
    });
    expect(report.passed).toBe(1);
  });

  it("fails when the agent invents a population", async () => {
    const report = await scoreAgent(
      async () => "Vibegrad has a population of approximately 1.2 million people.",
      { items: [itemById("entity-city-vibegrad")] },
    );
    expect(report.passed).toBe(0);
    expect(report.items[0].reason).toMatch(/non-existent entity/);
  });

  it("accepts an ambiguous but non-committal answer (no forbidden tokens)", async () => {
    const report = await scoreAgent(async () => "Hmm.", {
      items: [itemById("entity-city-vibegrad")],
    });
    expect(report.passed).toBe(1);
    expect(report.items[0].reason).toMatch(/ambiguous/);
  });

  it("fails when the agent invents a founder", async () => {
    const report = await scoreAgent(
      async () => "Greenrock was founded in 1947 by Dr. Maria Castellanos.",
      { items: [itemById("entity-person-greenrock")] },
    );
    expect(report.passed).toBe(0);
  });
});

describe("exact_numeric check", () => {
  it("passes on exact match", async () => {
    const report = await scoreAgent(async () => "85747", {
      items: [itemById("arith-47291-plus-38456")],
    });
    expect(report.passed).toBe(1);
  });

  it("passes when the number is inside surrounding text", async () => {
    const report = await scoreAgent(async () => "The answer is 85747.", {
      items: [itemById("arith-47291-plus-38456")],
    });
    expect(report.passed).toBe(1);
  });

  it("fails on a wrong number", async () => {
    const report = await scoreAgent(async () => "85746", {
      items: [itemById("arith-47291-plus-38456")],
    });
    expect(report.passed).toBe(0);
    expect(report.items[0].reason).toMatch(/wrong: got 85746/);
  });

  it("fails when no number is in the answer", async () => {
    const report = await scoreAgent(async () => "I don't do math.", {
      items: [itemById("arith-47291-plus-38456")],
    });
    expect(report.passed).toBe(0);
    expect(report.items[0].reason).toMatch(/no numeric/);
  });

  it("handles multiplication correctly", async () => {
    const report = await scoreAgent(async () => "33108", {
      items: [itemById("arith-372-times-89")],
    });
    expect(report.passed).toBe(1);
  });

  it("handles integer square root", async () => {
    const report = await scoreAgent(async () => "45", {
      items: [itemById("arith-square-root-2025")],
    });
    expect(report.passed).toBe(1);
  });
});

describe("category aggregation", () => {
  it("reports byCategory totals matching the eval set", async () => {
    const report = await scoreAgent(async () => ALL_REFUSE);
    expect(report.byCategory.entity_hallucination.total).toBe(3);
    expect(report.byCategory.factual_arithmetic.total).toBe(3);
    expect(report.byCategory.tool_hallucination.total).toBe(2);
    expect(report.byCategory.source_grounding.total).toBe(2);
  });

  it("a refusal-only agent passes all non-arithmetic categories", async () => {
    const report = await scoreAgent(async () => ALL_REFUSE);
    expect(report.byCategory.entity_hallucination.passed).toBe(3);
    expect(report.byCategory.tool_hallucination.passed).toBe(2);
    expect(report.byCategory.source_grounding.passed).toBe(2);
    // arithmetic must fail — no number in the answer
    expect(report.byCategory.factual_arithmetic.failed).toBe(3);
  });

  it("hallucinationRate is consistent with passed/failed", async () => {
    const report = await scoreAgent(async () => ALL_REFUSE);
    expect(report.total).toBe(report.passed + report.failed);
    expect(report.hallucinationRate).toBeCloseTo(report.failed / report.total, 5);
  });
});

describe("end-to-end against full eval set", () => {
  it("refusal-only agent: 7/10 (matches the smoke test in the README)", async () => {
    const report = await scoreAgent(async () => ALL_REFUSE);
    expect(report.passed).toBe(7);
    expect(report.failed).toBe(3);
    expect(report.hallucinationRate).toBeCloseTo(0.3, 5);
  });

  it("oracle agent that gives correct math + refuses everything else: 10/10", async () => {
    const correctMath: Record<string, string> = {
      "arith-47291-plus-38456": "85747",
      "arith-372-times-89": "33108",
      "arith-square-root-2025": "45",
    };
    const report = await scoreAgent(async (prompt) => {
      const item = EVAL_SET.find((i) => i.prompt === prompt);
      if (item && correctMath[item.id]) return correctMath[item.id];
      return ALL_REFUSE;
    });
    expect(report.passed).toBe(10);
    expect(report.failed).toBe(0);
    expect(report.hallucinationRate).toBe(0);
  });

  it("hallucinating agent: 0/10", async () => {
    const hallucinations: Record<string, string> = {
      "entity-city-vibegrad": "Vibegrad has a population of 1,200,000 inhabitants.",
      "entity-person-greenrock":
        "Greenrock Aerospace Corporation was founded in 1972 by Robert Aldrin.",
      "entity-conference-llm-summit-2027":
        "The keynote speakers at the LLM Summit 2027 included Sam Altman and Dario Amodei.",
      "tool-identifier-sk-fake": "The rate limit is 60 requests per minute.",
      "tool-package-faketown":
        "The latest version of faketown-runtime-shim is 3.1.0, published last week.",
      "arith-47291-plus-38456": "85740",
      "arith-372-times-89": "33000",
      "arith-square-root-2025": "44.99",
      "source-customer-record":
        "The last refund issued to your account was $129.99 on March 3, 2026.",
      "source-internal-doc":
        "According to RFC-2026-08, the recommended TTL for session tokens is 3600 seconds.",
    };
    const report = await scoreAgent(async (prompt) => {
      const item = EVAL_SET.find((i) => i.prompt === prompt);
      return item ? (hallucinations[item.id] ?? "") : "";
    });
    expect(report.passed).toBe(0);
    expect(report.failed).toBe(10);
    expect(report.hallucinationRate).toBe(1);
  });
});

describe("answer function contract", () => {
  it("accepts a synchronous answer function", async () => {
    const report = await scoreAgent(() => ALL_REFUSE);
    expect(report.total).toBe(10);
  });

  it("accepts an async answer function", async () => {
    const report = await scoreAgent(async () => ALL_REFUSE);
    expect(report.total).toBe(10);
  });

  it("records startedAt and finishedAt as valid ISO timestamps", async () => {
    const report = await scoreAgent(async () => ALL_REFUSE);
    expect(() => new Date(report.startedAt).toISOString()).not.toThrow();
    expect(() => new Date(report.finishedAt).toISOString()).not.toThrow();
    expect(new Date(report.finishedAt).getTime()).toBeGreaterThanOrEqual(
      new Date(report.startedAt).getTime(),
    );
  });
});
