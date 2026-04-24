# Vibefixing product voice — for contributors to `supervisor-discover`

Everything this package writes — `SUMMARY.md`, `report.md`, `ROLLOUT.md`,
`combos/*.md`, `findings.json.rationale`, CLI stderr — has to sound like a
senior engineer helping a vibe-coder ship safely. Never like a pentest
report.

## Golden rule

> Don't tell the user they have security findings. Tell them what their
> agent can do, why that could break production, and exactly where to put
> the gate.

Every string added to this package gets judged against that rule first.

## The 10 operational rules

1. **Every report answers 6 questions in order:**
   1. What is this repo?
   2. What can the agent do?
   3. What can go wrong?
   4. Where in my code?
   5. How do I fix it?
   6. How do I deploy safely?

2. **Order findings by blast radius, never by scanner:**
   money → real-world-actions → customer-data → business-data → LLM-tool-use → general.

3. **Per-finding format:**
   ```
   🔒 Gate N <surface> call-site(s) (~N min)
   🔴 Problem: <concrete real-world scenario>
   📍 Where:   <file:line> · <file:line>
   ✅ Fix:     Wrap with @supervised('<action_type>'). Policy: <plain English>.
   ```

4. **Problem = real scenario, never abstract API name.**
   NOT: "Calendar API detected."
   YES: "The agent can create or edit calendar events. A prompt injection
   could create phishing invites or silently delete legit meetings."

5. **Combos explain multiplicative risk.** Mandatory template:
   *Why it matters / Evidence / Minimum guard / Ideal guard.*
   Combo = attack path, not feature list.

6. **Severity = 3 dimensions.** Impact (money/data/account/real-world) ×
   Confidence (high/medium/low) × Priority (P0/P1/P2/Info). Not one bucket.

7. **Every fix includes:** wrapper + policy + rollout mode + where to paste
   + how to verify. Never just "fix this".

8. **Rollout copy is mandatory:** shadow → sample → enforce with explicit
   advance criteria (≥20 observed calls / FP rate <5% / no legit path in
   `would_block_in_shadow` / p95 <200ms). One-line rollback (env var flip).

9. **"What I'm not worried about" section** is present in every report —
   it reduces anxiety and signals criterion. E.g.: *"No payment SDKs
   detected. No direct UPDATE/DELETE on customer tables."*

10. **CLI output ≤20 lines.** Stack / agent / tier counts / critical combos
    / "open SUMMARY.md first". Explanation lives in markdown, not terminal.

## Per-artifact role (don't blur these)

| Artifact | Role | Reader state of mind |
|---|---|---|
| `SUMMARY.md` | "What I'd do today" — action-first | *I want the 3–5 things to fix now* |
| `report.md` | Technical tier breakdown | *I want the full detail* |
| `ROLLOUT.md` | Safe deploy playbook (shadow→sample→enforce) | *How do I ship this without breaking prod* |
| `findings.json` | Machine-readable, stable schema | *CI / diff / automation* |
| `combos/*.md` | Per-combo attack path + copy-paste fix | *This specific risk is me; walk me through it* |
| CLI stderr | ≤20 lines, pointer to `SUMMARY.md` | *Did the scan work; what do I open next* |

## Vocabulary

**Use freely (allow-list):** blocks, gates, catches, wraps, ships, breaks prod,
touch customer data, move money, call tools, shadow mode, enforce mode, wrap
point, blast radius, chokepoint.

**Never in headlines (deny-list — footnotes OK):** OWASP, LLM01/LLM02/…,
compliance, governance, policy engine, threat pipeline, risk scoring,
auditability, CVSS, vulnerability. These are fine in technical footnotes at
the bottom of a tier section, never in titles or opening lines.

**Severity copy (use these strings):**
- High: *"Can cause real-world impact, money movement, data loss, privilege
  change, or customer-facing action."*
- Medium: *"Could become dangerous depending on arguments or runtime
  context."*
- Low: *"Likely legitimate, but worth confirming if controlled by agent
  input."*
- Info: *"Maps the surface. No guard required yet."*

**Fix-time estimates (realistic):**
- 5 min: single function wrapper
- 15 min: 2–3 call-sites of the same pattern
- 30 min: policy + allowlist
- 1h: combo playbook
- 1–2 days: framework-level orchestrator integration

## Pre-commit checklist

Before merging a change that touches any of the files above, the output of
a live scan must pass:

- [ ] First line states the repo type in plain English (no scanner name in headline).
- [ ] Findings are ordered by blast radius, not scanner.
- [ ] Each priority item renders 🔒 Gate N / 🔴 Problem / 📍 Where / ✅ Fix.
- [ ] Problem statements are real-world scenarios, not API names.
- [ ] Combos use *Why it matters / Evidence / Minimum guard / Ideal guard*.
- [ ] "What I'm not worried about" section present when applicable.
- [ ] `ROLLOUT.md` has shadow → sample → enforce with advance criteria
      (≥20 calls / FP <5% / p95 <200ms) and one-line rollback.
- [ ] No OWASP / vulnerability / compliance / CVSS in any headline.
- [ ] Fix-time estimates are realistic (5 min to 1–2 days).
- [ ] No Spanish (`acá`, `wrappear`, `gatear`, `apalancamiento`, …),
      no Spanglish.
- [ ] Run: `grep -rE "(acá|tenés|podés|wrappear|gatear|apalancamiento)" packages/supervisor-discover/src/` → zero matches.

## Reference example

The gold-standard SUMMARY.md for a repo with voice, calendar, LLM, and
filesystem surfaces:

```md
# repo — security review

Scanned a LangChain agent with voice, calendar, and filesystem access.

## Do this first

🔒 Gate voice + telephony call-sites (~16 min)
🔴 Problem: this repo can synthesize voices AND place phone calls. A prompt
    injection controlling either tool turns it into a vishing recipe.
📍 Where: elevenlabs-tts/index.ts:104 · initiate-voice-task/index.ts:105
✅ Fix: @supervised('tool_use') + allowlist destination numbers and approved voices.

🔒 Gate calendar call-sites (~15 min)
🔴 Problem: the agent can create or edit Google Calendar events. A prompt
    injection could create phishing invites or silently delete legitimate meetings.
📍 Where: routes/calendar.ts:140 · routes/calendar.ts:345 · routes/calendar.ts:362
✅ Fix: @supervised('tool_use') + invited-domain allowlist.

🔒 Gate LLM call-site (~5 min)
🔴 Problem: prompts can be injected, oversized, or looped before the tool fires.
📍 Where: llm/openai.ts:370
✅ Fix: @supervised('tool_use') + prompt-length cap + required `tool_name`.

## Critical combos

🔴 Voice cloning + outbound calls
Review any trace where both tools fire in the same session.

🟡 LLM + filesystem writes
Allowlist write paths; block outside `/tmp` or approved data dirs.

## What I'm not worried about

- No payment SDKs detected.
- No direct UPDATE/DELETE on customer tables.

## Suggested timeline

- **Today (~45 min):** apply the 🔒 wrap points. Deploy in shadow.
- **2–3 days:** let observations accumulate. Watch `would_block_in_shadow`.
- **Day 4+:** flip `SUPERVISOR_ENFORCEMENT_MODE=enforce` once FP rate < 5%.
```

That's the target quality bar. Every contributor writing copy for this
package should be able to point at any line in their output and map it back
to one of the 10 rules.

---

*Voice guide lives here permanently. When a new scanner or template gets
added, the pre-commit checklist above applies — no exceptions.*
