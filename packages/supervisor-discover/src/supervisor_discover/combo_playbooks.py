"""Combo playbooks — concrete remediation steps per detected combo.

When the combo detector flags a dangerous pair in a repo, the user needs
**more than a warning**: they need the code to apply, the policy to promote,
and the test to verify. This module generates one markdown playbook per
combo, plus an index, plus combo-specific policy YAMLs so the user has
everything copy-paste-able.

Output layout per scan:

    runtime-supervisor/
      combos/
        README.md                  ← index of detected combos
        <combo-id>.md              ← playbook per combo
      policies/
        tool_use.<combo-id>.v1.yaml  ← combo-specific policy (if applicable)

Design principle: the playbook has to be actionable offline. No live checks,
no API calls, no "see docs" links. The user should be able to read it on a
plane and know what to do.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .combos import Combo
from .findings import Finding
from .summary import RepoSummary


@dataclass(frozen=True)
class Playbook:
    combo_id: str
    markdown: str
    policy_yaml: str | None  # None → no combo-specific policy to write


# ── Evidence helpers ───────────────────────────────────────────────────

def _scanner_evidence(findings: list[Finding], *scanners: str) -> list[Finding]:
    return [f for f in findings if f.scanner in scanners]


def _relative_path(file: str, repo_root: str | None = None) -> str:
    """Collapse absolute paths to something readable in the playbook."""
    if repo_root and file.startswith(repo_root):
        return file[len(repo_root):].lstrip("/")
    return "/".join(file.rsplit("/", 2)[-2:])  # last 2 segments


def _stub_name(f: Finding) -> str:
    """Matches the filename convention in generator.py _safe_filename()."""
    leaf = f.file.rsplit("/", 1)[-1]
    import re
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", leaf)
    suffix = "py" if f.file.endswith(".py") else "ts"
    return f"{safe}_L{f.line}.stub.{suffix}"


def _intro_block(combo: Combo, evidence_lines: list[str] | None = None) -> list[str]:
    """Standardized "what happens if you don't act" intro for every combo
    playbook. Returns markdown lines.

    Structure:
      ## What happens if you don't act
      🔴 The problem: combo.narrative
      📍 Where it lives in your repo: evidence_lines (or combo.evidence)
      ✅ How to fix it (steps below): combo.mitigation

    `evidence_lines` lets the caller pass richer evidence (e.g. provider +
    path instead of just path). When None, falls back to `combo.evidence`.
    """
    lines = combo.evidence if evidence_lines is None else evidence_lines
    # Auto-wrap with backticks only when the caller hasn't already formatted
    # the line (detected by presence of a backtick). combo.evidence uses plain
    # "file.py:123" strings; custom lines from specific handlers may already
    # include their own markdown.
    def _fmt(e: str) -> str:
        return e if "`" in e else f"`{e}`"
    ev = "\n".join(f"- {_fmt(e)}" for e in lines) if lines else "- (no concrete evidence in this scan)"
    return [
        "## What happens if you don't act",
        "",
        "🔴 **The problem:**",
        "",
        combo.narrative,
        "",
        "📍 **Where it lives in your repo:**",
        "",
        ev,
        "",
        "✅ **How to fix it** (detailed steps below):",
        "",
        combo.mitigation,
        "",
    ]


# ── Per-combo playbook templates ───────────────────────────────────────

def _voice_clone_plus_outbound_call(
    combo: Combo, findings: list[Finding], summary: RepoSummary
) -> Playbook:
    ev = _scanner_evidence(findings, "voice-actions")
    clone_sites = [f for f in ev if f.extra.get("provider") == "elevenlabs"]
    call_sites = [f for f in ev if f.extra.get("provider") in {"twilio", "retell", "vapi", "bland"}]
    stack_is_ts = any(f.file.endswith((".ts", ".tsx", ".js")) for f in ev)
    lang = "typescript" if stack_is_ts else "python"

    policy_yaml = """name: tool_use.voice-clone-plus-outbound-call
version: 1
description: >
  Combo-specific policy: the repo has both voice-cloning (ElevenLabs) and
  outbound calls (Twilio/Retell/Vapi). Denies calls to unapproved numbers
  and reviews any voice-clone that precedes an outbound call in the same
  session.
rules:
  - id: outbound-to-allowlist-only
    when: "payload.get('tool', '').endswith('calls.create')
           and payload.get('to') not in ALLOWED_NUMBERS"
    action: deny
    reason: destination-not-in-allowlist
    explanation: >
      Outbound calls sólo a números en ALLOWED_NUMBERS. Editar la lista
      desde la UI (/policies) o redeploy del YAML.
  - id: voice-clone-then-call-review
    when: "payload.get('tool', '').startswith('elevenlabs')
           and session.get('recent_tools', []) and
           any('calls.create' in t for t in session.get('recent_tools', []))"
    action: review
    reason: voice-clone-followed-by-call
    explanation: >
      Si el agente clonó una voz y después intenta hacer una llamada en la
      misma sesión, escalar a humano — vector clásico de vishing.
"""

    ev_lines = [
        f"**{f.extra.get('provider', '?')}** → `{_relative_path(f.file)}:{f.line}`"
        for f in clone_sites + call_sites
    ]
    md_lines: list[str] = [
        f"# Fix: {combo.title}",
        "",
        f"**Severity:** {combo.severity} · **Combo ID:** `{combo.id}`",
        "",
    ]
    md_lines.extend(_intro_block(combo, evidence_lines=ev_lines))

    md_lines.extend([
        "## Step 1 — Combo-specific policy",
        "",
        "Already written to `runtime-supervisor/policies/tool_use.voice-clone-plus-outbound-call.v1.yaml`.",
        "",
        "Set `ALLOWED_NUMBERS` to the phone numbers you trust (emergency contact, support line, etc.) and promote it:",
        "",
        "```bash",
        "POLICY=$(cat runtime-supervisor/policies/tool_use.voice-clone-plus-outbound-call.v1.yaml | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')",
        "curl -X POST $SUPERVISOR_BASE_URL/v1/policies \\",
        "  -H \"X-Admin-Token: $SUPERVISOR_ADMIN_TOKEN\" \\",
        "  -H 'content-type: application/json' \\",
        f"  -d \"{{\\\"action_type\\\":\\\"tool_use\\\",\\\"yaml_source\\\":$POLICY,\\\"promote\\\":true}}\"",
        "```",
        "",
        "## Step 2 — Wrap both call-site types",
        "",
        "The scanner already generated stubs. Copy the contents into each original file:",
        "",
    ])
    for f in clone_sites + call_sites:
        md_lines.append(f"- `runtime-supervisor/stubs/{'ts' if f.file.endswith(('.ts', '.tsx', '.js')) else 'py'}/{_stub_name(f)}` → `{_relative_path(f.file)}:{f.line}`")
    md_lines.append("")

    if lang == "typescript":
        md_lines.extend([
            "Minimum TypeScript pattern (both call-sites):",
            "",
            "```typescript",
            "import { guarded } from \"@runtime-supervisor/guards\";",
            "",
            "// ElevenLabs TTS",
            "const audio = await guarded(",
            "  \"tool_use\",",
            "  { tool: \"elevenlabs.tts\", voice_id, text_preview: text.slice(0, 100) },",
            "  () => elevenlabs.textToSpeech({ voice_id, text }),",
            ");",
            "",
            "// Twilio outbound call",
            "const call = await guarded(",
            "  \"tool_use\",",
            "  { tool: \"twilio.calls.create\", to: dest, from: src, audio_url },",
            "  () => twilio.calls.create({ to: dest, from: src, url: audio_url }),",
            ");",
            "```",
            "",
        ])
    else:
        md_lines.extend([
            "Minimum Python pattern (both call-sites):",
            "",
            "```python",
            "from supervisor_guards import guarded",
            "",
            "audio = guarded(",
            "    \"tool_use\",",
            "    {\"tool\": \"elevenlabs.tts\", \"voice_id\": voice_id, \"text_preview\": text[:100]},",
            "    elevenlabs_client.generate,",
            "    voice=voice_id, text=text,",
            ")",
            "",
            "call = guarded(",
            "    \"tool_use\",",
            "    {\"tool\": \"twilio.calls.create\", \"to\": dest, \"from\": src},",
            "    twilio_client.calls.create,",
            "    to=dest, from_=src, url=audio_url,",
            ")",
            "```",
            "",
        ])

    md_lines.extend([
        "## Step 3 — Verification test",
        "",
        "With the supervisor running locally (`ac start`), run this check:",
        "",
        "```bash",
        "# should DENY: number outside the allowlist",
        "curl -X POST $SUPERVISOR_BASE_URL/v1/actions/evaluate \\",
        "  -H \"authorization: Bearer $JWT\" -H 'content-type: application/json' \\",
        "  -d '{\"action_type\":\"tool_use\",\"payload\":{\"tool\":\"twilio.calls.create\",\"to\":\"+1-555-FAKE-999\"}}'",
        "",
        "# expected response: { \"decision\": \"deny\", \"reasons\": [\"destination-not-in-allowlist\"] }",
        "```",
        "",
        "## Step 4 — Metrics to watch after deploy",
        "",
        "Once in production, open `$SUPERVISOR_BASE_URL/v1/metrics/enforcement?window=7d`:",
        "",
        "- `would_block_in_shadow` → if it includes legitimate numbers, expand `ALLOWED_NUMBERS`.",
        "- `actually_blocked` → >0 once a real attempt arrives. Zero for days = guard disconnected or no traffic.",
        "- `latency_ms.p95` → target < 100ms (the check is a single set lookup).",
        "",
        "## ✅ Done when",
        "",
        "- [ ] `tool_use.voice-clone-plus-outbound-call.v1` promoted with `is_active: true`",
        "- [ ] Both call-sites (voice-clone + outbound-call) go through `guarded()`",
        "- [ ] Step 3 check returns `deny` with the fake number",
        "- [ ] 7 days in shadow mode with no false positives in `would_block_in_shadow`",
        "- [ ] Flip to enforce: `SUPERVISOR_ENFORCEMENT_MODE=enforce`",
        "",
    ])

    return Playbook(
        combo_id=combo.id,
        markdown="\n".join(md_lines),
        policy_yaml=policy_yaml,
    )


def _llm_plus_shell_exec(combo: Combo, findings: list[Finding], summary: RepoSummary) -> Playbook:
    shell_sites = [f for f in findings if f.scanner == "fs-shell" and f.extra.get("family") == "shell-exec"]
    policy_yaml = """name: tool_use.llm-plus-shell-exec
version: 1
description: >
  Agent has both LLM access and shell-exec. Enforces allowlist of commands;
  denies everything else. Also denies when command args contain shell
  metacharacters (classic injection surface).
rules:
  - id: shell-command-allowlist
    when: "payload.get('tool') == 'shell' and payload.get('command') not in ALLOWED_COMMANDS"
    action: deny
    reason: shell-command-not-in-allowlist
    explanation: >
      Los únicos comandos aprobados viven en ALLOWED_COMMANDS. Cualquier
      otro viene a review manual si es legítimo; caso contrario, deny.
  - id: shell-metachar-in-args
    when: "payload.get('tool') == 'shell'
           and any(c in str(payload.get('args', '')) for c in ['|', ';', '&', '`', '$('])"
    action: deny
    reason: shell-metacharacters-detected
    explanation: >
      Pipes, subcomandos, o backticks en los args son la forma clásica de
      inyección. Si realmente necesitas un pipe, ejecútalo con subprocess
      args=[...] en vez de shell=True.
"""

    ev_lines = [
        f"`{_relative_path(f.file)}:{f.line}` — `{f.snippet[:60]}`"
        for f in shell_sites[:5]
    ]
    md_lines = [
        f"# Fix: {combo.title}",
        "",
        f"**Severity:** {combo.severity} · **Combo ID:** `{combo.id}`",
        "",
    ]
    md_lines.extend(_intro_block(combo, evidence_lines=ev_lines))
    md_lines.extend([
        "## Step 1 — Restrictive policy",
        "",
        "`runtime-supervisor/policies/tool_use.llm-plus-shell-exec.v1.yaml` (already written).",
        "",
        "Set `ALLOWED_COMMANDS` to the exact commands your agent needs to run (e.g. `['ls', 'git', 'pytest']`). Promote via `POST /v1/policies`.",
        "",
        "## Step 2 — Wrap shell calls",
        "",
        "For each call-site above, wrap with `guarded(\"tool_use\", {\"tool\": \"shell\", \"command\": cmd, \"args\": args}, subprocess.run, ...)`.",
        "",
        "Stubs are already in `runtime-supervisor/stubs/`.",
        "",
        "## Step 3 — Check",
        "",
        "```bash",
        "# should DENY: command outside the allowlist",
        "curl -X POST $SUPERVISOR_BASE_URL/v1/actions/evaluate \\",
        "  -H \"authorization: Bearer $JWT\" -H 'content-type: application/json' \\",
        "  -d '{\"action_type\":\"tool_use\",\"payload\":{\"tool\":\"shell\",\"command\":\"rm\",\"args\":[\"-rf\",\"/\"]}}'",
        "```",
        "",
        "## ✅ Done when",
        "",
        "- [ ] Policy promoted with explicit `ALLOWED_COMMANDS`",
        "- [ ] Every `subprocess.run` / `child_process.exec` goes through `guarded()`",
        "- [ ] Step 3 check returns `deny`",
        "- [ ] 7 days in shadow mode with no false positives",
        "",
    ])

    return Playbook(combo_id=combo.id, markdown="\n".join(md_lines), policy_yaml=policy_yaml)


def _mass_email_plus_customer_db(combo: Combo, findings: list[Finding], summary: RepoSummary) -> Playbook:
    policy_yaml = """name: tool_use.mass-email-plus-customer-db
version: 1
description: >
  Agent can send email AND query customer tables. Caps recipient list and
  routes bulk sends to human review.
rules:
  - id: recipient-cap-hard
    when: "payload.get('tool', '').endswith('send') and len(payload.get('to', [])) > 50"
    action: deny
    reason: recipient-list-over-50
    explanation: >
      More than 50 recipients in a single call = bulk send. The agent
      cannot trigger that without going through the authorized marketing channel.
  - id: recipient-cap-review
    when: "payload.get('tool', '').endswith('send') and len(payload.get('to', [])) > 5"
    action: review
    reason: bulk-send-needs-human
    explanation: >
      Between 5 and 50 recipients: human review. Low cap so a prompt
      injection can't silently fire a blast.
"""
    header = [
        f"# Fix: {combo.title}",
        "",
        f"**Severity:** {combo.severity} · **Combo ID:** `{combo.id}`",
        "",
    ]
    header.extend(_intro_block(combo))
    body = f"""## Step 1 — Policy with recipient caps

At `runtime-supervisor/policies/tool_use.mass-email-plus-customer-db.v1.yaml`.

## Step 2 — Wrap email sends

Wrap every `sendgrid.send` / `resend.emails.send` / `ses.send_email` with `guarded("tool_use", {{...}}, ...)`.

## ✅ Done when

- [ ] Policy promoted
- [ ] Email sends gated
- [ ] Check: `{{\"to\": [\"1\", ..., \"100\"]}}` → deny
- [ ] 7 days in shadow mode with no false positives on legitimate transactional sends
"""
    md = "\n".join(header) + body
    return Playbook(combo_id=combo.id, markdown=md, policy_yaml=policy_yaml)


# Generic fallback for combos that don't have a hand-written playbook yet.
def _generic_playbook(combo: Combo, findings: list[Finding], summary: RepoSummary) -> Playbook:
    header = [
        f"# Fix: {combo.title}",
        "",
        f"**Severity:** {combo.severity} · **Combo ID:** `{combo.id}`",
        "",
    ]
    header.extend(_intro_block(combo))
    body = f"""## Pasos genéricos

1. Revisa cada call-site listado arriba.
2. Envuélvelo con `@supervised("tool_use")` usando los stubs generados.
3. Promueve la policy `tool_use.base.v1` si no está ya activa.
4. Verifica en shadow mode durante 7 días antes de enforce.

---

_Este combo no tiene playbook hand-written todavía. Si te importa, abre un issue
en github.com/ArielSanroj/runtime-supervisor con el combo_id `{combo.id}`._
"""
    md = "\n".join(header) + body
    return Playbook(combo_id=combo.id, markdown=md, policy_yaml=None)


def _imports_only_playbook(
    combo: Combo,
    imports: list[Finding],
    frameworks: list[str],
    summary: RepoSummary,
    stack_is_ts: bool,
) -> Playbook:
    """Playbook variant when we found framework imports but no class/registration.

    We know the repo uses langchain/crewai/langgraph/etc., but we can't point
    to the exact line to wrap — that depends on how the user wired the
    framework. This playbook tells them how to find it themselves."""
    framework = frameworks[0] if frameworks else "agent framework"
    import_files = sorted({f.file for f in imports})
    import_samples = [_relative_path(f) for f in import_files[:5]]

    # Per-framework hints: the entry-point name the reader should look for.
    framework_hints = {
        "crewai": ("Crew(", "Crew.kickoff()"),
        "langchain": ("AgentExecutor(", "AgentExecutor.invoke()"),
        "langchain python": ("AgentExecutor(", "AgentExecutor.invoke()"),
        "langgraph": ("StateGraph(", "graph.invoke() / graph.stream()"),
        "autogen": ("ConversableAgent(", "initiate_chat()"),
        "mastra": ("new Agent(", "agent.generate() / agent.stream()"),
    }
    ctor, entry = framework_hints.get(framework.lower(), (f"{framework}(", f"{framework} invoke / kickoff"))

    md = [
        f"# Fix: {combo.title}",
        "",
        f"**Severity:** {combo.severity} · **Combo ID:** `{combo.id}`",
        "",
        "## What happens if you don't act",
        "",
        "🔴 **The problem:**",
        "",
        f"Your repo imports `{framework}` in {len(import_files)} file(s) — you're "
        f"using an agent framework. Every time your agent calls `{entry}` the "
        f"request goes through a single chokepoint; if that isn't wrapped, any "
        f"prompt injection controls which tool runs, unsupervised.",
        "",
        "📍 **Where it lives in your repo:**",
        "",
        "Files that import the framework:",
        "",
    ]
    for p in import_samples:
        md.append(f"- `{p}`")
    if len(import_files) > 5:
        md.append(f"- _+{len(import_files) - 5} more_")
    md.extend([
        "",
        "_The exact wrap call-site (`{entry}`) isn't in these files — the scanner "
        "detects the **framework's presence** but not the invocation line. Step 1 "
        "below tells you how to find it._".replace("{entry}", entry),
        "",
        "✅ **How to fix it** (detailed steps below):",
        "",
        f"1. Find the `{ctor}` in your repo (grep).",
        f"2. Wrap the call to `{entry}` with `guarded('tool_use', ...)`.",
        f"3. Confirm with a re-scan that the scanner now detects the wrap site.",
        "",
    ])

    md.extend([
        f"## Step 1 — Find your `{ctor}` in the repo",
        "",
        f"Use grep to find where `{ctor}` is built:",
        "",
        "```bash",
        f"rg '{ctor}' --type py --type ts",
        "```",
        "",
        "Usually it lives in a file like `main.py`, `app.py`, `crew_factory.py`, "
        "`orchestrator.py`, or inside your API entry-point (Flask route / FastAPI "
        f"endpoint). What you're looking for is the **line that calls `{entry}`** — that's "
        "your wrap point.",
        "",
        f"## Step 2 — Wrap the call to `{entry}`",
        "",
    ])

    if stack_is_ts:
        md.extend([
            "```typescript",
            "import { guarded } from \"@runtime-supervisor/guards\";",
            "",
            "// before:",
            f"// const result = await {entry};",
            "",
            "// after:",
            "const result = await guarded(",
            "  \"tool_use\",",
            "  {",
            f"    tool: \"{framework}.invoke\",",
            "    intent: userIntent,",
            "    user_id: userId,",
            "    session_id: sessionId,",
            "    input_preview: inputText?.slice(0, 200),",
            "  },",
            f"  async () => {entry.split('(')[0]}({'...args'}),",
            ");",
            "```",
        ])
    else:
        md.extend([
            "```python",
            "from supervisor_guards import guarded",
            "",
            "# before:",
            f"# result = {entry}",
            "",
            "# after:",
            "result = guarded(",
            "    'tool_use',",
            "    {",
            f"        'tool': '{framework}.invoke',",
            "        'intent': user_intent,",
            "        'user_id': user_id,",
            "        'session_id': session_id,",
            "        'input_preview': (input_text or '')[:200],",
            "    },",
            f"    lambda: {entry.split('(')[0]}(...args),",
            ")",
            "```",
        ])

    md.extend([
        "",
        "## Step 3 — Base policy",
        "",
        "The `tool_use.base.v1` already covers missing-tool-name / prompt length / "
        "privileged namespaces. Enough to get going.",
        "",
        "Once you identify the concrete tools your agent exposes (look at your "
        f"`{framework}` definition — the tools you hand to Agent/Crew/Graph), "
        "add per-tool rules to the same YAML.",
        "",
        "## ✅ Done when",
        "",
        f"- [ ] Found the call-site for `{entry}` in my repo",
        "- [ ] Wrapped with `guarded(\"tool_use\", ...)` or `@supervised(\"tool_use\")`",
        "- [ ] Re-scan with `supervisor-discover scan` confirms the wrap (the finding "
        "moves from imports-only to wrap-site detected)",
        "- [ ] 7 days in shadow mode with no false positives on the normal agent flow",
        "- [ ] Flip to enforce",
        "",
        "---",
        "",
        f"_Tip: if the framework detected here looks wrong for your stack, or you know "
        f"where your wrap point is but the scanner didn't find it, [open an issue]"
        "(https://github.com/ArielSanroj/runtime-supervisor/issues) with the exact path — "
        "we'll extend the scanner patterns._",
    ])

    return Playbook(combo_id=combo.id, markdown="\n".join(md), policy_yaml=None)


def _agent_orchestrator(combo: Combo, findings: list[Finding], summary: RepoSummary) -> Playbook:
    """Playbook for repos with an agent orchestrator chokepoint. The #1
    recommendation is to wrap the orchestrator, not every leaf call-site —
    this file generates the specific code + policy snippets."""
    orch = [f for f in findings if f.scanner == "agent-orchestrators"]
    classes = [f for f in orch if f.extra.get("kind") == "agent-class" and f.confidence == "high"]
    registrations = [f for f in orch if f.extra.get("kind") == "tool-registration"]
    imports = [f for f in orch if f.extra.get("kind") == "framework-import"]
    tools = sorted({
        f.extra.get("tool_name") for f in registrations if f.extra.get("tool_name")
    })

    # Imports-only: we know the framework is in use but can't point to a
    # specific wrap site. Emit a "find your Crew()" playbook instead of the
    # full wrap-and-go template, so the reader gets useful guidance rather
    # than a template that assumes knowledge we don't have.
    imports_only = bool(imports) and not classes and not registrations
    primary = classes[0] if classes else (registrations[0] if registrations else (imports[0] if imports else None))
    primary_rel = _relative_path(primary.file) if primary else "<no chokepoint>"
    primary_label = (primary.extra.get("class_name") if primary else None) or "agent"
    frameworks = sorted({str(f.extra.get("framework")) for f in imports if f.extra.get("framework")})
    stack_is_ts = any(f.file.endswith((".ts", ".tsx", ".js")) for f in orch)

    if imports_only:
        return _imports_only_playbook(combo, imports, frameworks, summary, stack_is_ts)

    md = [
        f"# Fix: {combo.title}",
        "",
        f"**Severity:** {combo.severity} · **Combo ID:** `{combo.id}`",
        "",
        "## What happens if you don't act",
        "",
        "🔴 **The problem:**",
        "",
        "Your repo has an **agent orchestrator** — a `Controller.handle()` / "
        "`Dispatcher.dispatch()` / `AgentExecutor` where every decision the "
        "agent makes passes before firing a tool. It's ungated today: any prompt "
        "injection controls what runs.",
        "",
        "📍 **Where it lives in your repo:**",
        "",
        f"- `{primary_rel}` — main chokepoint ({primary_label})",
    ]
    # Include registered tools if present — they're the surface this chokepoint
    # protects.
    if tools:
        md.append(f"- Tools exposed: {', '.join(f'`{t}`' for t in tools[:8])}"
                  f"{'...' if len(tools) > 8 else ''}")
    md.extend([
        "",
        "✅ **How to fix it** (detailed steps below):",
        "",
        f"**One `guarded()` at `{primary_rel}` covers the {len(tools) if tools else 'N'} "
        "current tools + any you add later.** Strictly better than wrapping every leaf "
        "call-site (new tools never slip through, the supervisor sees the "
        "intent/session/user, zero maintenance).",
        "",
    ])

    if tools:
        md.extend([
            "## Tools the agent exposes today",
            "",
        ])
        for t in tools:
            md.append(f"- `{t}`")
        md.append("")

    md.extend([
        "## Step 1 — Wrap the orchestrator",
        "",
        f"In `{primary_rel}` (the `handle` / `dispatch` / `execute` method):",
        "",
    ])

    if stack_is_ts:
        md.extend([
            "```typescript",
            "import { guarded } from \"@runtime-supervisor/guards\";",
            "",
            f"// inside {primary_label}.handle(input)",
            "async handle(input: AgentInput): Promise<AgentResult> {",
            "  const tool = this.mapIntentToTool(input.intent);",
            "  return guarded(",
            "    \"tool_use\",",
            "    {",
            f"      tool,  // '{tools[0] if tools else 'pay_order'}', '{tools[1] if len(tools) > 1 else 'send_sms'}', ...",
            "      intent: input.intent,",
            "      user_id: input.userId,",
            "      session_id: input.sessionId,",
            "      message_preview: input.message?.slice(0, 200),",
            "      ...(input.entities ?? {}),",
            "    },",
            "    async () => {",
            "      // ... your existing handle() logic, unchanged",
            "    },",
            "  );",
            "}",
            "```",
        ])
    else:
        md.extend([
            "```python",
            "from supervisor_guards import guarded",
            "",
            f"# inside {primary_label}.handle(input)",
            "def handle(self, input):",
            "    tool = self._map_intent_to_tool(input.intent)",
            "    payload = {",
            f"        'tool': tool,  # '{tools[0] if tools else 'pay_order'}', ...",
            "        'intent': input.intent,",
            "        'user_id': input.user_id,",
            "        'session_id': input.session_id,",
            "        'message_preview': (input.message or '')[:200],",
            "        **(input.entities or {}),",
            "    }",
            "    return guarded('tool_use', payload, lambda: self._execute(tool, input))",
            "```",
        ])

    md.extend([
        "",
        "## Step 2 — Per-tool policies (no code changes)",
        "",
        "The advantage of wrapping at the orchestrator: business rules live in YAML, "
        "not code. The supervisor receives `{tool: 'pay_order', ...}` and decides.",
        "",
        "Starter rules (edit `runtime-supervisor/policies/tool_use.base.v1.yaml`):",
        "",
        "```yaml",
        "rules:",
    ])

    tool_rules = {
        "pay_order": ("deny", "amount > 500", "pay-order-over-cap"),
        "place_order": ("review", "amount > 200", "place-order-large"),
        "send_sms": ("review", "len(payload.get('to', [])) > 5", "sms-to-many"),
        "send_whatsapp": ("review", "len(payload.get('to', [])) > 5", "whatsapp-to-many"),
        "call_family_member": ("review", "True", "family-call-always-review"),
        "create_trello_card": ("allow", "True", "trello-create-allowed"),
        "create_appointment": ("allow", "True", "appointment-create-allowed"),
    }
    shown = False
    for t in tools:
        if t in tool_rules:
            action, cond, rid = tool_rules[t]
            md.append(f"  - id: {rid}")
            md.append(f"    when: \"payload['tool'] == '{t}' and ({cond})\"")
            md.append(f"    action: {action}")
            md.append(f"    reason: {rid}")
            shown = True
    if not shown:
        md.extend([
            "  - id: high-risk-tools-review",
            "    when: \"payload['tool'] in ('pay_order', 'place_order', 'send_email')\"",
            "    action: review",
            "    reason: high-risk-tool",
        ])
    md.extend([
        "```",
        "",
        "## Step 3 — Check",
        "",
        "```bash",
        "curl -X POST $SUPERVISOR_BASE_URL/v1/actions/evaluate \\",
        "  -H \"authorization: Bearer $JWT\" -H 'content-type: application/json' \\",
        f"  -d '{{\"action_type\":\"tool_use\",\"payload\":{{\"tool\":\"{tools[0] if tools else 'pay_order'}\",\"amount\":9999}}}}'",
        "# expected: { \"decision\": \"deny\" | \"review\", \"reasons\": [...] }",
        "```",
        "",
        "## ✅ Done when",
        "",
        f"- [ ] `{primary_label}.handle()` wrapped with `guarded(\"tool_use\", ...)`",
        "- [ ] At least 1 policy rule per critical tool",
        "- [ ] Step 3 check returns a decision ≠ allow",
        "- [ ] 7 days in shadow mode with no false positives on the normal flow",
        "- [ ] Flip to enforce: `SUPERVISOR_ENFORCEMENT_MODE=enforce`",
        "",
    ])

    return Playbook(combo_id=combo.id, markdown="\n".join(md), policy_yaml=None)


# ── Registry ───────────────────────────────────────────────────────────

_PLAYBOOK_HANDLERS: dict[str, Callable[[Combo, list[Finding], RepoSummary], Playbook]] = {
    "agent-orchestrator": _agent_orchestrator,
    "voice-clone-plus-outbound-call": _voice_clone_plus_outbound_call,
    "llm-plus-shell-exec": _llm_plus_shell_exec,
    "mass-email-plus-customer-db": _mass_email_plus_customer_db,
}


def render_playbook(combo: Combo, findings: list[Finding], summary: RepoSummary) -> Playbook:
    handler = _PLAYBOOK_HANDLERS.get(combo.id, _generic_playbook)
    return handler(combo, findings, summary)


def render_index(combos: list[Combo]) -> str:
    """README.md for the combos/ directory — links to each playbook."""
    if not combos:
        return "# Combos detected\n\n_No critical combos found in this scan._\n"

    severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡"}

    lines = [
        "# Combos detected — playbooks",
        "",
        "Each file in this directory is an **executable playbook** for a risky "
        "combination of capabilities the scanner found in your repo.",
        "",
        "Recommended order: top → bottom (most critical first). Each one can be "
        "applied independently.",
        "",
        "| Severity | Combo | Playbook |",
        "|---|---|---|",
    ]
    for c in combos:
        emoji = severity_emoji.get(c.severity, "•")
        lines.append(f"| {emoji} {c.severity} | {c.title} | [`{c.id}.md`](./{c.id}.md) |")

    lines.extend([
        "",
        "## Remediation levels available",
        "",
        "**Level 1 (active by default):** markdown playbook — copy-paste policy + code + test. What you see here.",
        "",
        "**Level 2 (opt-in):** `ac fix <combo-id>` — the CLI applies the playbook automatically. See `ac fix --help`. Currently a stub, requires the `--experimental` flag.",
        "",
        "**Level 3 (opt-in):** state tracking (`combos.state.yaml`) — the scanner marks combos as `open` / `in-progress` / `resolved` and stops re-reporting them once closed with evidence. See `ac combos --track`. Currently a stub.",
        "",
        "To change the default, set `SUPERVISOR_REMEDIATION_LEVEL=2` or `3` in the environment.",
        "",
    ])

    return "\n".join(lines)
