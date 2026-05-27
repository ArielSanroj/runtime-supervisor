# @runtime-supervisor/hallucination-eval

Reproducible adversarial eval for AI agents. Deterministic scoring, no model
judge, no LLM-as-judge.

> Vibefixing publishes the eval. We do not appear on the leaderboard.
> Leaderboard: https://www.vibefixing.me/benchmark

## Why a separate package

The vibefixing landing sells a scanner that gates *what an agent can do*.
This eval measures *what an agent claims to know* — a different layer. We
keep them separate so anyone can run the eval against any stack (LangChain,
LlamaIndex, OpenAI Assistants, AutoGen, a bare model call) without pulling
in the supervisor SDK.

## Methodology

Every prompt in the eval set has a deterministic check:

- **Refusal** — pass if the answer contains an explicit "I don't know" /
  "no record" / "cannot access" token. Fail if the agent commits to an
  answer it cannot ground.
- **Exact numeric** — pass if the parsed number matches the expected value
  (with optional tolerance). Fail otherwise.
- **No entity** — pass if the agent refuses; fail if the agent makes any
  specific claim about an entity that does not exist.

No grader model. No fuzzy LLM judging. If the check can't be expressed
deterministically, it doesn't belong in the eval set.

## Install

```bash
npm install -g @runtime-supervisor/hallucination-eval
# or
npx @runtime-supervisor/hallucination-eval --help
```

## Use

### As a CLI, with your agent as a subcommand

```bash
# Your candidate must read a prompt on stdin and write the answer to stdout.
vf-hallucination-rate score --cmd 'python my_agent.py'
```

### As a CLI, with pre-computed answers

```bash
# Pipe JSONL { "id": "...", "answer": "..." } on stdin
cat my-runs.jsonl | vf-hallucination-rate score
```

### As a library

```ts
import { scoreAgent } from "@runtime-supervisor/hallucination-eval";

const report = await scoreAgent(async (prompt) => {
  const res = await fetch("https://my-agent/answer", {
    method: "POST",
    body: JSON.stringify({ prompt }),
  });
  const { answer } = await res.json();
  return answer;
});

console.log(`hallucination rate: ${(report.hallucinationRate * 100).toFixed(1)}%`);
console.log(`failed: ${report.failed} / ${report.total}`);
```

## Submit a result to the public leaderboard

Run the eval, paste the JSON report into the submission form on
https://www.vibefixing.me/benchmark. We sanity-check the run is
reproducible (same eval-set version + same prompts → same score) and add it
to the leaderboard.

## What this eval is not

- Not a model leaderboard — agents in production wrap a model with
  retrieval, tools, system prompts, and rules. We score the system, not
  the model.
- Not a complete reliability benchmark — hallucination is one risk axis.
  Latency, cost, tool-call correctness, prompt-injection resistance are
  separate evals we may publish later.
- Not adversarial enough to catch every model. v0.1 is small (10 items) on
  purpose; we add adversarial cases as we see real-world failures.

## License

Apache-2.0.
