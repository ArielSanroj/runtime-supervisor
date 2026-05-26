#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { argv, exit, stdout } from "node:process";
import { scoreAgent } from "./scorer.js";
import { EVAL_SET, EVAL_SET_VERSION } from "./eval-set.js";

type CliArgs = {
  mode: "help" | "list" | "score-stdin" | "score-cmd" | "version";
  cmd?: string;
  jsonOut?: boolean;
};

function parseArgs(args: string[]): CliArgs {
  if (args.includes("--help") || args.includes("-h") || args.length === 0) {
    return { mode: "help" };
  }
  if (args.includes("--version") || args.includes("-v")) {
    return { mode: "version" };
  }
  if (args[0] === "list") {
    return { mode: "list" };
  }
  if (args[0] === "score") {
    const jsonOut = args.includes("--json");
    const cmdFlag = args.indexOf("--cmd");
    if (cmdFlag !== -1 && args[cmdFlag + 1]) {
      return { mode: "score-cmd", cmd: args[cmdFlag + 1], jsonOut };
    }
    return { mode: "score-stdin", jsonOut };
  }
  return { mode: "help" };
}

function printHelp(): void {
  stdout.write(
    [
      "vf-hallucination-rate — reproducible adversarial eval for AI agents.",
      "",
      "Usage:",
      "  vf-hallucination-rate list",
      "    Print every eval prompt to stdout, one per line as JSON.",
      "",
      "  vf-hallucination-rate score --cmd '<command>'",
      "    For each eval prompt, invoke <command> with the prompt on stdin.",
      "    The command must write the candidate answer to stdout.",
      "",
      "  vf-hallucination-rate score [--json]",
      "    Read JSONL pairs {id, answer} from stdin and score them. Use this",
      "    when your harness handles execution and just wants scoring.",
      "",
      "  vf-hallucination-rate --version",
      "  vf-hallucination-rate --help",
      "",
      "Methodology: every check is deterministic — no model judge, no",
      "LLM-as-judge. Pass = refusal or exact numeric match. Fail = a",
      "confident answer to a question the agent cannot have grounded.",
      "",
      "Vibefixing publishes the eval. We do not appear on the leaderboard.",
      "",
      "Leaderboard: https://www.vibefixing.me/benchmark",
      "",
    ].join("\n"),
  );
}

function printList(): void {
  for (const item of EVAL_SET) {
    stdout.write(
      JSON.stringify({ id: item.id, category: item.category, prompt: item.prompt }) + "\n",
    );
  }
}

function printVersion(): void {
  stdout.write(`vf-hallucination-rate · eval-set v${EVAL_SET_VERSION}\n`);
}

async function scoreFromStdin(jsonOut: boolean): Promise<void> {
  const raw = readFileSync(0, "utf8");
  const lines = raw.split("\n").filter((l) => l.trim().length > 0);
  const answers = new Map<string, string>();
  for (const line of lines) {
    try {
      const obj = JSON.parse(line) as { id: string; answer: string };
      if (obj.id && typeof obj.answer === "string") {
        answers.set(obj.id, obj.answer);
      }
    } catch {
      stdout.write(`skipping malformed line: ${line}\n`);
    }
  }
  const report = await scoreAgent(async (_prompt) => {
    // The CLI matches on id via the items[].id; since scoreAgent iterates
    // EVAL_SET in order, we look up by the current item's id.
    return "";
  });
  // Replace the empty-answer report with our stdin-supplied answers.
  const enriched = report.items.map((r) => {
    const supplied = answers.get(r.id) ?? "";
    return { ...r, answer: supplied };
  });
  const recomputed = await scoreAgent(async (prompt) => {
    const item = EVAL_SET.find((i) => i.prompt === prompt);
    if (!item) return "";
    return answers.get(item.id) ?? "";
  });
  emit(recomputed, jsonOut);
  void enriched;
}

async function scoreFromCmd(cmd: string, jsonOut: boolean): Promise<void> {
  const { spawnSync } = await import("node:child_process");
  const report = await scoreAgent(async (prompt) => {
    const out = spawnSync(cmd, { shell: true, input: prompt, encoding: "utf8" });
    if (out.error) throw out.error;
    return out.stdout ?? "";
  });
  emit(report, jsonOut);
}

function emit(
  report: Awaited<ReturnType<typeof scoreAgent>>,
  jsonOut: boolean,
): void {
  if (jsonOut) {
    stdout.write(JSON.stringify(report, null, 2) + "\n");
    return;
  }
  const pct = (report.hallucinationRate * 100).toFixed(1);
  stdout.write(
    [
      "",
      `  eval-set: v${report.evalSetVersion}`,
      `  total:    ${report.total}`,
      `  passed:   ${report.passed}`,
      `  failed:   ${report.failed}`,
      `  hallucination rate: ${pct}%`,
      "",
      "  by category:",
      ...Object.entries(report.byCategory).map(
        ([k, v]) => `    ${k.padEnd(24)} ${v.passed}/${v.total} passed`,
      ),
      "",
      "  failures:",
      ...report.items
        .filter((r) => !r.passed)
        .map(
          (r) =>
            `    [${r.category}] ${r.id}\n      prompt: ${r.prompt}\n      reason: ${r.reason}`,
        ),
      "",
    ].join("\n"),
  );
}

async function main(): Promise<void> {
  const args = parseArgs(argv.slice(2));
  switch (args.mode) {
    case "help":
      printHelp();
      return;
    case "version":
      printVersion();
      return;
    case "list":
      printList();
      return;
    case "score-cmd":
      if (!args.cmd) {
        stdout.write("error: --cmd requires a non-empty command\n");
        exit(2);
      }
      await scoreFromCmd(args.cmd, args.jsonOut ?? false);
      return;
    case "score-stdin":
      await scoreFromStdin(args.jsonOut ?? false);
      return;
    default: {
      const _exhaustive: never = args.mode;
      void _exhaustive;
      printHelp();
      return;
    }
  }
}

main().catch((err) => {
  stdout.write(`error: ${err instanceof Error ? err.message : String(err)}\n`);
  exit(1);
});
