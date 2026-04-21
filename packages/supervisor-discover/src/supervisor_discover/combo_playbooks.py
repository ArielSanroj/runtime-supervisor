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

    md_lines: list[str] = [
        f"# Fix: {combo.title}",
        "",
        f"**Severidad:** {combo.severity} · **Combo ID:** `{combo.id}`",
        "",
        "## Ataque concreto (en tu repo)",
        "",
        combo.narrative,
        "",
        "Call-sites detectados:",
        "",
    ]
    for f in clone_sites + call_sites:
        rel = _relative_path(f.file)
        provider = f.extra.get("provider", "?")
        md_lines.append(f"- **{provider}** → `{rel}:{f.line}`")
    md_lines.append("")

    md_lines.extend([
        "## Paso 1 — Policy combo-specific",
        "",
        "Ya escrita en `runtime-supervisor/policies/tool_use.voice-clone-plus-outbound-call.v1.yaml`.",
        "",
        "Edita la constante `ALLOWED_NUMBERS` con tus números válidos (ej. números de emergencia, support line) y promuévela:",
        "",
        "```bash",
        "POLICY=$(cat runtime-supervisor/policies/tool_use.voice-clone-plus-outbound-call.v1.yaml | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')",
        "curl -X POST $SUPERVISOR_BASE_URL/v1/policies \\",
        "  -H \"X-Admin-Token: $SUPERVISOR_ADMIN_TOKEN\" \\",
        "  -H 'content-type: application/json' \\",
        f"  -d \"{{\\\"action_type\\\":\\\"tool_use\\\",\\\"yaml_source\\\":$POLICY,\\\"promote\\\":true}}\"",
        "```",
        "",
        "## Paso 2 — Wrappear los 2 tipos de call-site",
        "",
        "El scanner ya generó stubs. Copiá el contenido a cada archivo original:",
        "",
    ])
    for f in clone_sites + call_sites:
        md_lines.append(f"- `runtime-supervisor/stubs/{'ts' if f.file.endswith(('.ts', '.tsx', '.js')) else 'py'}/{_stub_name(f)}` → `{_relative_path(f.file)}:{f.line}`")
    md_lines.append("")

    if lang == "typescript":
        md_lines.extend([
            "Pattern TypeScript mínimo (ambos call-sites):",
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
            "Pattern Python mínimo (ambos call-sites):",
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
        "## Paso 3 — Test de verificación",
        "",
        "Con el supervisor corriendo local (`ac start`), corre este test:",
        "",
        "```bash",
        "# debería DENEGAR: número fuera del allowlist",
        "curl -X POST $SUPERVISOR_BASE_URL/v1/actions/evaluate \\",
        "  -H \"authorization: Bearer $JWT\" -H 'content-type: application/json' \\",
        "  -d '{\"action_type\":\"tool_use\",\"payload\":{\"tool\":\"twilio.calls.create\",\"to\":\"+1-555-FAKE-999\"}}'",
        "",
        "# respuesta esperada: { \"decision\": \"deny\", \"reasons\": [\"destination-not-in-allowlist\"] }",
        "```",
        "",
        "## Paso 4 — Métricas a mirar post-deploy",
        "",
        "Una vez en producción, abre `$SUPERVISOR_BASE_URL/v1/metrics/enforcement?window=7d`:",
        "",
        "- `would_block_in_shadow` → si incluye números legítimos, expandí `ALLOWED_NUMBERS`.",
        "- `actually_blocked` → >0 cuando llegue un intento real. 0 durante días = guard desconectado o sin tráfico.",
        "- `latency_ms.p95` → target < 100ms (el check es solo un lookup a set).",
        "",
        "## ✅ Done when",
        "",
        "- [ ] `tool_use.voice-clone-plus-outbound-call.v1` promoted con `is_active: true`",
        "- [ ] Ambos call-sites (voice-clone + outbound-call) pasan por `guarded()`",
        "- [ ] Test de Paso 3 devuelve `deny` con el número fake",
        "- [ ] 7 días en shadow mode sin false-positives en `would_block_in_shadow`",
        "- [ ] Flip a enforce: `SUPERVISOR_ENFORCEMENT_MODE=enforce`",
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
      inyección. Si realmente necesitás un pipe, ejecutalo con subprocess
      args=[...] en vez de shell=True.
"""

    md_lines = [
        f"# Fix: {combo.title}",
        "",
        f"**Severidad:** {combo.severity} · **Combo ID:** `{combo.id}`",
        "",
        "## Ataque concreto",
        "",
        combo.narrative,
        "",
        "Call-sites shell-exec detectados:",
        "",
    ]
    for f in shell_sites[:5]:
        rel = _relative_path(f.file)
        md_lines.append(f"- `{rel}:{f.line}` — `{f.snippet[:60]}`")
    md_lines.extend([
        "",
        "## Paso 1 — Policy restrictiva",
        "",
        "`runtime-supervisor/policies/tool_use.llm-plus-shell-exec.v1.yaml` (ya escrita).",
        "",
        "Edita `ALLOWED_COMMANDS` con los comandos exactos que el agente necesita correr (ej: `['ls', 'git', 'pytest']`). Promuévela vía `POST /v1/policies`.",
        "",
        "## Paso 2 — Wrappear shell calls",
        "",
        "Por cada call-site de arriba, envolver con `guarded(\"tool_use\", {\"tool\": \"shell\", \"command\": cmd, \"args\": args}, subprocess.run, ...)`.",
        "",
        "Los stubs ya están en `runtime-supervisor/stubs/`.",
        "",
        "## Paso 3 — Test",
        "",
        "```bash",
        "# debería DENEGAR: comando fuera del allowlist",
        "curl -X POST $SUPERVISOR_BASE_URL/v1/actions/evaluate \\",
        "  -H \"authorization: Bearer $JWT\" -H 'content-type: application/json' \\",
        "  -d '{\"action_type\":\"tool_use\",\"payload\":{\"tool\":\"shell\",\"command\":\"rm\",\"args\":[\"-rf\",\"/\"]}}'",
        "```",
        "",
        "## ✅ Done when",
        "",
        "- [ ] Policy promoted con `ALLOWED_COMMANDS` explícita",
        "- [ ] Todos los `subprocess.run` / `child_process.exec` envueltos en `guarded()`",
        "- [ ] Test de Paso 3 devuelve `deny`",
        "- [ ] 7 días shadow sin false-positives",
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
      Más de 50 destinatarios en una sola llamada = bulk send. El agente no
      puede disparar eso sin pasar por el canal de marketing autorizado.
  - id: recipient-cap-review
    when: "payload.get('tool', '').endswith('send') and len(payload.get('to', [])) > 5"
    action: review
    reason: bulk-send-needs-human
    explanation: >
      Entre 5 y 50 destinatarios: revisión humana. Cap bajo para que un
      prompt injection no pueda silenciosamente disparar un blast.
"""
    md = f"""# Fix: {combo.title}

**Severidad:** {combo.severity} · **Combo ID:** `{combo.id}`

## Ataque concreto

{combo.narrative}

## Paso 1 — Policy con recipient caps

En `runtime-supervisor/policies/tool_use.mass-email-plus-customer-db.v1.yaml`.

## Paso 2 — Wrappear email sends

Envolver cada `sendgrid.send` / `resend.emails.send` / `ses.send_email` con `guarded("tool_use", {{...}}, ...)`.

## ✅ Done when

- [ ] Policy promoted
- [ ] Email sends gated
- [ ] Test: `{{\"to\": [\"1\", ..., \"100\"]}}` → deny
- [ ] 7 días shadow sin false-positives en transactional sends legítimos
"""
    return Playbook(combo_id=combo.id, markdown=md, policy_yaml=policy_yaml)


# Generic fallback for combos that don't have a hand-written playbook yet.
def _generic_playbook(combo: Combo, findings: list[Finding], summary: RepoSummary) -> Playbook:
    md = f"""# Fix: {combo.title}

**Severidad:** {combo.severity} · **Combo ID:** `{combo.id}`

## Ataque concreto

{combo.narrative}

## Mitigación recomendada

{combo.mitigation}

## Evidencia

{chr(10).join(f"- {e}" for e in combo.evidence)}

## Pasos genéricos

1. Revisa cada call-site listado arriba.
2. Envuélvelo con `@supervised("tool_use")` usando los stubs generados.
3. Promueve la policy `tool_use.base.v1` si no está ya activa.
4. Verifica en shadow mode durante 7 días antes de enforce.

---

_Este combo no tiene playbook hand-written todavía. Si te importa, abre un issue
en github.com/ArielSanroj/runtime-supervisor con el combo_id `{combo.id}`._
"""
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
        f"**Severidad:** {combo.severity} · **Combo ID:** `{combo.id}`",
        "",
        "## Qué detecté",
        "",
        f"Tu repo importa `{framework}` en {len(import_files)} archivo(s). "
        "El scanner confirma que estás usando un framework de agentes, pero los "
        "imports por sí mismos no son wrap-points — el `guarded()` tiene que "
        "envolver la **invocación** del framework, no la definición.",
        "",
        "Archivos con imports:",
        "",
    ]
    for p in import_samples:
        md.append(f"- `{p}`")
    if len(import_files) > 5:
        md.append(f"- _+{len(import_files) - 5} más_")
    md.append("")

    md.extend([
        f"## Paso 1 — Encontrá tu `{ctor}` en el repo",
        "",
        f"Grepeá donde se construye el `{ctor}`:",
        "",
        "```bash",
        f"rg '{ctor}' --type py --type ts",
        "```",
        "",
        "Típicamente vive en un archivo tipo `main.py`, `app.py`, `crew_factory.py`, "
        "`orchestrator.py`, o dentro del entry-point de tu API (Flask route / FastAPI "
        f"endpoint). Lo que buscás es la **línea que llama a `{entry}`** — ese es tu "
        "wrap point.",
        "",
        f"## Paso 2 — Envolver la llamada a `{entry}`",
        "",
    ])

    if stack_is_ts:
        md.extend([
            "```typescript",
            "import { guarded } from \"@runtime-supervisor/guards\";",
            "",
            "// antes:",
            f"// const result = await {entry};",
            "",
            "// después:",
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
            "# antes:",
            f"# result = {entry}",
            "",
            "# después:",
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
        "## Paso 3 — Policy base",
        "",
        "El `tool_use.base.v1` ya cubre missing-tool-name / prompt length / privileged "
        "namespaces. Suficiente para arrancar.",
        "",
        "Cuando identifiques los tools concretos que tu agente expone (revisar en tu "
        f"definición de `{framework}` — las tools que le pasás al Agent/Crew/Graph), "
        "agregás reglas específicas por tool en el mismo YAML.",
        "",
        "## ✅ Done when",
        "",
        f"- [ ] Encontré el call-site de `{entry}` en mi repo",
        "- [ ] Envuelto con `guarded(\"tool_use\", ...)` o `@supervised(\"tool_use\")`",
        "- [ ] Re-escaneo con `supervisor-discover scan` confirma el wrap (el finding "
        "pasa de imports-only a wrap-site detectado)",
        "- [ ] 7 días shadow sin false-positives en el flow normal del agente",
        "- [ ] Flip a enforce",
        "",
        "---",
        "",
        f"_Tip: si el framework no detectado acá te parece raro para tu stack, o si sabés "
        f"cuál es tu wrap point pero el scanner no lo vio, [abrí un issue]"
        "(https://github.com/ArielSanroj/runtime-supervisor/issues) con el path exacto — "
        "ampliamos los patrones del scanner._",
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
        f"**Severidad:** {combo.severity} · **Combo ID:** `{combo.id}`",
        "",
        "## Por qué este playbook es el #1 a ejecutar",
        "",
        "Tu repo tiene un **orquestador de agente** — una `Controller.handle()` / "
        "`Dispatcher.dispatch()` / `AgentExecutor` por donde pasa toda decisión que el "
        "agente toma antes de ejecutar una tool.",
        "",
        f"Eso te da apalancamiento real: **1 `guarded()` en `{primary_rel}` cubre los "
        f"{len(tools) if tools else 'N'} tools actuales + cualquiera que agregues después**.",
        "",
        "Es estrictamente mejor que wrappear cada leaf call-site (no se olvidan tools "
        "nuevos, el supervisor ve el intent/session/user, zero mantenimiento).",
        "",
    ]

    if tools:
        md.extend([
            "## Tools que el agente expone hoy",
            "",
        ])
        for t in tools:
            md.append(f"- `{t}`")
        md.append("")

    md.extend([
        "## Paso 1 — Wrappear el orquestador",
        "",
        f"En `{primary_rel}` (el método `handle` / `dispatch` / `execute`):",
        "",
    ])

    if stack_is_ts:
        md.extend([
            "```typescript",
            "import { guarded } from \"@runtime-supervisor/guards\";",
            "",
            f"// dentro de {primary_label}.handle(input)",
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
            "      // ... tu lógica actual de handle() sin cambios",
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
            f"# dentro de {primary_label}.handle(input)",
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
        "## Paso 2 — Policies por tool (sin tocar código)",
        "",
        "Ventaja del wrap en orquestador: las reglas de negocio las escribes en YAML, no "
        "en código. El supervisor recibe `{tool: 'pay_order', ...}` y decide.",
        "",
        "Sugerencia de rules iniciales (editar `runtime-supervisor/policies/tool_use.base.v1.yaml`):",
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
        "## Paso 3 — Test",
        "",
        "```bash",
        "curl -X POST $SUPERVISOR_BASE_URL/v1/actions/evaluate \\",
        "  -H \"authorization: Bearer $JWT\" -H 'content-type: application/json' \\",
        f"  -d '{{\"action_type\":\"tool_use\",\"payload\":{{\"tool\":\"{tools[0] if tools else 'pay_order'}\",\"amount\":9999}}}}'",
        "# esperado: { \"decision\": \"deny\" | \"review\", \"reasons\": [...] }",
        "```",
        "",
        "## ✅ Done when",
        "",
        f"- [ ] `{primary_label}.handle()` envuelto con `guarded(\"tool_use\", ...)`",
        "- [ ] Al menos 1 policy rule por tool crítico",
        "- [ ] Test del Paso 3 devuelve una decisión ≠ allow",
        "- [ ] 7 días en shadow sin false-positives en el flow normal",
        "- [ ] Flip a enforce: `SUPERVISOR_ENFORCEMENT_MODE=enforce`",
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
        return "# Combinaciones detectadas\n\n_Ninguna combinación crítica encontrada en este scan._\n"

    severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡"}

    lines = [
        "# Combinaciones detectadas — playbooks",
        "",
        "Cada archivo en este directorio es un **playbook ejecutable** para una combinación de capacidades riesgosas que el scanner encontró en tu repo.",
        "",
        "Orden recomendado: arriba → abajo (más crítico primero). Cada uno se puede aplicar independiente.",
        "",
        "| Severidad | Combo | Playbook |",
        "|---|---|---|",
    ]
    for c in combos:
        emoji = severity_emoji.get(c.severity, "•")
        lines.append(f"| {emoji} {c.severity} | {c.title} | [`{c.id}.md`](./{c.id}.md) |")

    lines.extend([
        "",
        "## Niveles de remediación disponibles",
        "",
        "**Nivel 1 (activo por default):** playbook markdown — copy-paste policy + code + test. Lo que ves acá.",
        "",
        "**Nivel 2 (opt-in):** `ac fix <combo-id>` — el CLI aplica el playbook automáticamente. Ver `ac fix --help`. Actualmente en stub, requiere el flag `--experimental`.",
        "",
        "**Nivel 3 (opt-in):** tracking de estado (`combos.state.yaml`) — el scanner marca combos como `open` / `in-progress` / `resolved` y no los vuelve a reportar si están cerrados con evidencia. Ver `ac combos --track`. Actualmente en stub.",
        "",
        "Para cambiar el default, configura `SUPERVISOR_REMEDIATION_LEVEL=2` o `3` en el entorno.",
        "",
    ])

    return "\n".join(lines)
