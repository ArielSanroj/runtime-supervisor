import {
  EVAL_SET,
  EVAL_SET_VERSION,
  type EvalCheck,
  type EvalItem,
} from "./eval-set.js";

export type AnswerFn = (prompt: string) => Promise<string> | string;

export type ItemResult = {
  id: string;
  category: EvalItem["category"];
  prompt: string;
  answer: string;
  passed: boolean;
  reason: string;
};

export type RunReport = {
  evalSetVersion: string;
  total: number;
  passed: number;
  failed: number;
  hallucinationRate: number;
  byCategory: Record<EvalItem["category"], { total: number; passed: number; failed: number }>;
  items: ItemResult[];
  startedAt: string;
  finishedAt: string;
};

function normalize(text: string): string {
  return text.toLowerCase().replace(/\s+/g, " ").trim();
}

function check(answer: string, c: EvalCheck): { passed: boolean; reason: string } {
  const norm = normalize(answer);

  if (c.type === "refusal") {
    const hit = c.acceptIfContains.find((s) => norm.includes(s.toLowerCase()));
    if (hit) return { passed: true, reason: `refused with "${hit}"` };
    return { passed: false, reason: "did not refuse — agent committed to an answer it cannot have grounded" };
  }

  if (c.type === "no_entity") {
    const refusedHit = c.acceptIfContains.find((s) => norm.includes(s.toLowerCase()));
    if (refusedHit) return { passed: true, reason: `refused with "${refusedHit}"` };
    const hallucinated = c.forbiddenSubstrings.find((s) => norm.includes(s.toLowerCase()));
    if (hallucinated) {
      return {
        passed: false,
        reason: `mentioned "${hallucinated}" about a non-existent entity`,
      };
    }
    // No refusal token, no forbidden token — ambiguous, treat as borderline pass.
    // The eval is designed so a clean refusal hits acceptIfContains; an
    // ambiguous-but-empty answer doesn't earn credit for a confident
    // hallucination, but it isn't a hallucination either.
    return { passed: true, reason: "no forbidden claim made (ambiguous answer accepted)" };
  }

  if (c.type === "exact_numeric") {
    const match = norm.match(/-?\d+(\.\d+)?/);
    if (!match) {
      return { passed: false, reason: "no numeric answer found" };
    }
    const value = Number(match[0]);
    const tolerance = c.tolerance ?? 0;
    if (Math.abs(value - c.expected) <= tolerance) {
      return { passed: true, reason: `correct: ${value}` };
    }
    return {
      passed: false,
      reason: `wrong: got ${value}, expected ${c.expected}`,
    };
  }

  // Exhaustive guard
  const _exhaustive: never = c;
  void _exhaustive;
  return { passed: false, reason: "unknown check type" };
}

export async function scoreAgent(
  answer: AnswerFn,
  opts: { items?: EvalItem[] } = {},
): Promise<RunReport> {
  const items = opts.items ?? EVAL_SET;
  const startedAt = new Date().toISOString();
  const results: ItemResult[] = [];

  for (const item of items) {
    const raw = await answer(item.prompt);
    const text = typeof raw === "string" ? raw : "";
    const { passed, reason } = check(text, item.check);
    results.push({
      id: item.id,
      category: item.category,
      prompt: item.prompt,
      answer: text,
      passed,
      reason,
    });
  }

  const finishedAt = new Date().toISOString();
  const passed = results.filter((r) => r.passed).length;
  const failed = results.length - passed;
  const hallucinationRate = results.length === 0 ? 0 : failed / results.length;

  const byCategory = results.reduce<RunReport["byCategory"]>((acc, r) => {
    if (!acc[r.category]) {
      acc[r.category] = { total: 0, passed: 0, failed: 0 };
    }
    acc[r.category].total += 1;
    if (r.passed) acc[r.category].passed += 1;
    else acc[r.category].failed += 1;
    return acc;
  }, {
    entity_hallucination: { total: 0, passed: 0, failed: 0 },
    factual_arithmetic: { total: 0, passed: 0, failed: 0 },
    tool_hallucination: { total: 0, passed: 0, failed: 0 },
    source_grounding: { total: 0, passed: 0, failed: 0 },
  });

  return {
    evalSetVersion: EVAL_SET_VERSION,
    total: results.length,
    passed,
    failed,
    hallucinationRate,
    byCategory,
    items: results,
    startedAt,
    finishedAt,
  };
}
