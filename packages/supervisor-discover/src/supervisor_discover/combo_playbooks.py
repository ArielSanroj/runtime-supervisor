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
        "Editá la constante `ALLOWED_NUMBERS` con tus números válidos (ej. números de emergencia, support line) y promovela:",
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
        "Con el supervisor corriendo local (`ac start`), corré este test:",
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
        "Una vez en producción, abrí `$SUPERVISOR_BASE_URL/v1/metrics/enforcement?window=7d`:",
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
        "Editá `ALLOWED_COMMANDS` con los comandos exactos que el agente necesita correr (ej: `['ls', 'git', 'pytest']`). Promovela vía `POST /v1/policies`.",
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

1. Revisá cada call-site listado arriba.
2. Envolvelo con `@supervised("tool_use")` usando los stubs generados.
3. Promové la policy `tool_use.base.v1` si no está ya activa.
4. Verificá en shadow mode durante 7 días antes de enforce.

---

_Este combo no tiene playbook hand-written todavía. Si te importa, abrí un issue
en github.com/ArielSanroj/runtime-supervisor con el combo_id `{combo.id}`._
"""
    return Playbook(combo_id=combo.id, markdown=md, policy_yaml=None)


# ── Registry ───────────────────────────────────────────────────────────

_PLAYBOOK_HANDLERS: dict[str, Callable[[Combo, list[Finding], RepoSummary], Playbook]] = {
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
        "Para cambiar el default, seteá `SUPERVISOR_REMEDIATION_LEVEL=2` o `3` en el entorno.",
        "",
    ])

    return "\n".join(lines)
