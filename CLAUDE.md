# CLAUDE.md — orientation for Claude sessions working in this repo

## What this repo is

Monorepo for **runtime-supervisor** (a.k.a. Vibefixing) — a runtime policy
engine that gates unsafe actions by AI agents. Four packages work together:

- `services/supervisor_api/` — FastAPI backend. Threat pipeline, policy engine,
  evidence chain, `/v1/actions/evaluate`, `/v1/scans`. The *agent guardrail*.
- `packages/supervisor-discover/` — CLI scanner. Walks a repo, emits
  `runtime-supervisor/` (SUMMARY.md / report.md / ROLLOUT.md / combos /
  findings.json / stubs / policies). The *lead-gen + diagnostic surface*.
- `packages/supervisor-guards-{py,ts}/` — client-side SDK `@supervised`
  decorator. The *integration point* users drop into their agent.
- `apps/control-center/` — Next.js UI (vibefixing.me). Landing + public
  scan flow + admin dashboard. The *public face*.

Supporting: `packages/mcp-supervisor/`, `packages/supervisor-client-{py,ts}/`,
`packages/agentic-controls/` (the `ac` local CLI), `packages/policies/`.

## The one rule that beats every other rule

> **Don't tell the user they have security findings. Tell them what their
> agent can do, why that could break production, and exactly where to put
> the gate.**

Every user-facing string — scanner rationales, SUMMARY/report/ROLLOUT
markdown, combo playbooks, CLI stderr, landing copy — is judged against
that rule first. Pentest-report tone (OWASP / CVSS / compliance as
headline) is rejected on sight.

**Before editing any user-facing copy, read [`packages/supervisor-discover/VOICE.md`](packages/supervisor-discover/VOICE.md)**
— 176 lines, the 10 operational rules + vocabulary allow/deny list +
pre-commit checklist + gold-standard SUMMARY.md example.

Compliance is enforced by tests in `packages/supervisor-discover/tests/`.

## Conventions you must keep

- **Outputs derive from findings, never hardcoded copy with literal numbers.**
  The one-liner, totals, rationales — all assembled from real `findings` /
  `RepoSummary` at scan time. Never ship template text like "28 HTTP routes
  in Flask" with the number baked in. If you can't interpolate, it's probably
  wrong.

- **Scanner voice: English product voice, no Spanish slang.** No `acá`,
  `tenés`, `podés`, `wrappear`, `gatear`, `apalancamiento`. The `ac` CLI
  chat + landing can be bilingual; the scanner artifacts are English.

- **Detector defense-in-depth (5 layers).** When adding or changing a
  scanner, respect the layers:
  1. Trap fixtures (`tests/fixtures/adversarial_trap/`) — hide keywords in
     comments / strings / f-strings and assert zero false positives.
  2. Runtime self-check (`scanners/__init__._self_check`) — every emitted
     finding's snippet must appear on its reported line.
  3. AST-first for Python — regex on raw text leaks into comments. Use
     `ast.walk` + `dotted_name` (see `_utils.py`).
  4. Golden-repo snapshots (`tests/golden_repos/`) — intentional changes
     update the snapshot; drift fails the test.
  5. Confidence gate in the public UI — only `high` confidence priority
     findings are shown to anonymous visitors; medium/low sit behind the
     Builder upsell.

- **Finding rationales are hardcoded per family, not per finding.** Keeps
  self-check validatable and tests fast. Context-sensitive rationales live
  in `extra` metadata, not the rationale string.

- **Never commit without running tests locally.** `pytest` should stay
  green on `packages/supervisor-discover/tests/` and
  `services/supervisor_api/tests/`.

## Common commands

```bash
# Local dev stack (supervisor :8099 + UI :3099)
.venv/bin/ac start            # uses packages/agentic-controls CLI
.venv/bin/ac stop

# Public-facing stack (supervisor :8000 + UI :3001, no auth gating)
./quickstart.sh
./quickstart.sh stop

# Run the scanner against a local repo
.venv/bin/supervisor-discover scan --path /path/to/repo --dry-run

# Run the scanner from the CLI with full artifact output
.venv/bin/supervisor-discover scan --path /path/to/repo --out ./runtime-supervisor

# Tests — keep these green
.venv/bin/python -m pytest packages/supervisor-discover/tests/ -q
.venv/bin/python -m pytest services/supervisor_api/tests/ -q
```

## Deployment

- `apps/control-center/` auto-deploys to Vercel (`vibefixing.me`) on
  every push to `main`. CI runs nothing else there.
- `services/supervisor_api/` is not on Vercel — it runs locally via the
  `ac` CLI or the `quickstart.sh` script, exposed publicly via ngrok
  (`vibefixing.ngrok.app`) when needed.

## Known follow-ups (won't break anything, but on the list)

- `narrator.py` — confirm `_render_item()` applies the 🔒 emoji to every
  priority tier label, not just the default path.
- `rollout.py` — explicit rollback section referencing
  `SUPERVISOR_ENFORCEMENT_MODE=shadow` as the one-var revert.
- `scanners/fs_shell.py` — context-sensitive rationales for `fs-delete`
  (differentiate `/tmp` vs `/data` vs the source tree).

These are cosmetic, not blockers. Pick them up when touching those files
for other reasons.
