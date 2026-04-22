"""`supervisor-discover` CLI entry point."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from . import __version__
from .classifier import TIER_ORDER, group_by_risk_tier, validate
from .generator import generate
from .scanners import scan_all
from .summary import build_summary, render_cli_stdout
from .templates import TIER_COPY


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="supervisor-discover",
        description="Scan an agent repo to find what the runtime-supervisor should guard.",
    )
    p.add_argument("--version", action="version", version=f"supervisor-discover {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    scan_p = sub.add_parser("scan", help="Scan and optionally write outputs")
    scan_p.add_argument("--path", default=".", help="Repo root to scan (default: cwd)")
    scan_p.add_argument("--out", default="runtime-supervisor", help="Output directory (default: ./runtime-supervisor)")
    scan_p.add_argument("--dry-run", action="store_true", help="Don't write files; print findings.json to stdout")
    scan_p.add_argument(
        "--refine",
        action="store_true",
        help="Pass top findings to Claude for repo-specific narratives. "
             "Requires ANTHROPIC_API_KEY. Falls back silently if unavailable.",
    )
    scan_p.add_argument(
        "--level",
        type=int,
        choices=[1, 2, 3],
        default=None,
        help="Remediation level (1=playbooks markdown, 2=auto-fix stub, 3=tracking stub). "
             "If omitted and running interactively, prompts. Default: 1.",
    )
    scan_p.add_argument(
        "--no-prompt",
        action="store_true",
        help="Never prompt for remediation level — use --level or default 1 silently. "
             "Useful for CI.",
    )
    scan_p.add_argument(
        "--show-resolved",
        action="store_true",
        help="Ignore combos.state.yaml — report all detected combos even if "
             "previously marked resolved. Useful for audit / regression check.",
    )

    sub.add_parser("init", help="Alias for `scan` with defaults that write to ./runtime-supervisor/")

    # Nivel 2 (opt-in) — auto-fix a combo. Stub; prints roadmap for now.
    fix_p = sub.add_parser(
        "fix",
        help="Nivel 2 (opt-in): auto-apply a combo playbook. Currently a stub — "
             "use the markdown playbook in runtime-supervisor/combos/ instead.",
    )
    fix_p.add_argument("combo_id", help="Combo id from runtime-supervisor/combos/README.md")
    fix_p.add_argument(
        "--experimental", action="store_true",
        help="Acknowledge this is opt-in and may touch your source files.",
    )
    fix_p.add_argument("--out", default="runtime-supervisor", help="Output directory")

    # Nivel 3 — combo state tracking. Marca combos como resolved y el próximo
    # scan los suprime del report. State file: runtime-supervisor/combos.state.yaml.
    combos_p = sub.add_parser(
        "combos",
        help="Nivel 3: gestiona el estado de los combos detectados "
             "(open / in-progress / resolved). `resolved` se suprime del próximo scan.",
    )
    combos_p.add_argument(
        "--out", default="runtime-supervisor",
        help="Directorio con combos.state.yaml (default: ./runtime-supervisor)",
    )
    combos_sub = combos_p.add_subparsers(
        dest="combos_verb", required=False,
        help="Verbo a ejecutar — sin argumento = list.",
    )

    combos_sub.add_parser(
        "list",
        help="Muestra el estado de cada combo detectado (default si se omite).",
    )
    resolve_p = combos_sub.add_parser(
        "resolve",
        help="Marca un combo como resolved. El próximo scan no lo reporta.",
    )
    resolve_p.add_argument("combo_id", help="ID del combo (ej: voice-clone-plus-outbound-call)")
    resolve_p.add_argument("--note", default="", help="Nota breve del por qué se cerró.")
    resolve_p.add_argument("--by", default=None, help="Quién lo cerró (email o handle).")

    in_progress_p = combos_sub.add_parser(
        "in-progress",
        help="Marca un combo como in-progress (se sigue reportando pero con nota).",
    )
    in_progress_p.add_argument("combo_id")
    in_progress_p.add_argument("--note", default="")

    reopen_p = combos_sub.add_parser(
        "reopen",
        help="Revierte un combo a open — vuelve a aparecer en scans futuros.",
    )
    reopen_p.add_argument("combo_id")

    combos_sub.add_parser(
        "clear",
        help="Borra combos.state.yaml — todos los combos vuelven a reportarse.",
    )

    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    # Subcommands that don't scan — handle early + return.
    if args.cmd == "fix":
        return _handle_fix(args)
    if args.cmd == "combos":
        return _handle_combos(args)

    root = Path(args.path if args.cmd == "scan" else ".").resolve()
    out = Path(args.out if args.cmd == "scan" else "runtime-supervisor").resolve()
    dry_run = bool(getattr(args, "dry_run", False))

    if not root.exists():
        print(f"error: path not found: {root}", file=sys.stderr)
        return 2

    # Refuse to scan $HOME — the user almost certainly meant a specific project.
    home = Path.home().resolve()
    if root == home:
        print(
            f"refusing to scan your home directory ({root}).\n"
            "cd into the project you want to supervise and re-run, or pass --path /abs/path/to/repo.",
            file=sys.stderr,
        )
        return 2

    t0 = time.perf_counter()
    findings = validate(scan_all(root))
    elapsed = time.perf_counter() - t0

    # Optional --refine: per-finding narrative enrichment via Claude.
    # No-ops gracefully when ANTHROPIC_API_KEY is missing so the CLI stays
    # usable in CI and offline without extra checks.
    if getattr(args, "refine", False):
        from .combos import detect_combos
        from .refine import refine_findings
        print("  refining narratives via Claude…", file=sys.stderr)
        findings = refine_findings(findings, build_summary(findings), detect_combos(findings))

    if dry_run:
        # Mirror the on-disk findings.json shape so CI diffs line up.
        summary = build_summary(findings)
        payload = {
            "repo_summary": summary.to_dict(),
            "findings": sorted(
                (f.to_dict() for f in findings),
                key=lambda d: (d["file"], d["line"], d["scanner"]),
            ),
        }
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    generate(
        findings, out, repo_root=root,
        include_resolved=bool(getattr(args, "show_resolved", False)),
    )
    _print_tier_summary(root, findings, elapsed, out)
    _prompt_remediation_level(findings, out, args)
    return 0


def _prompt_remediation_level(findings: list, out: Path, args: argparse.Namespace) -> None:
    """After scan + generate, show the remediation menu when combos exist.

    Resolution order (first match wins):
      1. --level flag  → explicit, no prompt
      2. SUPERVISOR_REMEDIATION_LEVEL env var → explicit, no prompt
      3. non-TTY or --no-prompt → silent default (1)
      4. interactive TTY → prompt, default 1 on Enter
    """
    from .combo_state import filter_reported, load, state_path_for
    from .combos import detect_combos

    combos = detect_combos(findings)
    # Nivel 3: no preguntar por combos ya marcados resolved (unless --show-resolved).
    if not getattr(args, "show_resolved", False):
        states = load(state_path_for(out))
        combos = filter_reported(combos, states)
    if not combos:
        return

    # Resolve level precedence.
    if args.level is not None:
        level = args.level
        _execute_level(level, combos, out, prompted=False)
        return

    env_level = os.environ.get("SUPERVISOR_REMEDIATION_LEVEL")
    if env_level in ("1", "2", "3"):
        _execute_level(int(env_level), combos, out, prompted=False)
        return

    if args.no_prompt or not sys.stdin.isatty() or not sys.stderr.isatty():
        _execute_level(1, combos, out, prompted=False)
        return

    # Interactive prompt.
    print("", file=sys.stderr)
    print(f"Combinaciones críticas detectadas: {len(combos)}", file=sys.stderr)
    print("", file=sys.stderr)
    print("¿Cómo quieres resolver los combos?", file=sys.stderr)
    print("  [1] Ver playbooks markdown (default, no toca tu código)", file=sys.stderr)
    print("      → runtime-supervisor/combos/ con pasos copy-paste", file=sys.stderr)
    print("  [2] Auto-fix (experimental, stub)", file=sys.stderr)
    print("      → el CLI aplica el playbook por ti. No implementado todavía.", file=sys.stderr)
    print("  [3] Tracking de estado (opt-in, stub)", file=sys.stderr)
    print("      → marca combos resueltos para que scans futuros no los re-reporten.", file=sys.stderr)
    print("", file=sys.stderr)

    try:
        choice = input("  Elige [1]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("", file=sys.stderr)
        choice = ""

    if choice == "":
        level = 1
    elif choice in ("1", "2", "3"):
        level = int(choice)
    else:
        print(f"  Opción inválida '{choice}', usando default 1.", file=sys.stderr)
        level = 1

    _execute_level(level, combos, out, prompted=True)


def _execute_level(level: int, combos: list, out: Path, *, prompted: bool) -> None:
    """Act on the chosen level. 1 is the real path; 2 and 3 explain + fall back."""
    if level == 1:
        readme = out / "combos" / "README.md"
        first = out / "combos" / f"{combos[0].id}.md"
        if prompted:
            print("", file=sys.stderr)
        print(f"-> {readme.relative_to(out.parent) if out.parent in readme.parents else readme}  ({len(combos)} combos)", file=sys.stderr)
        print(f"-> abre primero: {first.name}  ← más crítico", file=sys.stderr)
        return

    if level == 2:
        from .combo_autofix import explain
        print("", file=sys.stderr)
        print(explain(), file=sys.stderr)
        print("", file=sys.stderr)
        print("Cayendo a Nivel 1: runtime-supervisor/combos/ tiene los playbooks.", file=sys.stderr)
        return

    if level == 3:
        from .combo_state import explain
        print("", file=sys.stderr)
        print(explain(), file=sys.stderr)
        print("", file=sys.stderr)
        print("Combos detectados ahora mismo (aplica el playbook primero, luego marca resolved):", file=sys.stderr)
        for c in combos:
            print(f"  · {c.id}", file=sys.stderr)
        print("", file=sys.stderr)
        print("Cuando termines:", file=sys.stderr)
        for c in combos:
            print(f"  supervisor-discover combos resolve {c.id} --note \"...\"", file=sys.stderr)
        print("", file=sys.stderr)
        print("El próximo scan no los va a reportar. `combos list` muestra el estado.", file=sys.stderr)
        return


# Fallback one-line descriptions when the summary has nothing specific to
# add. Keeps the terminal output useful on repos with surfaces the scanner
# hasn't mapped yet.
_TIER_FALLBACK: dict[str, str] = {
    "money": "stripe · paypal · plaid (nada detectado)",
    "real_world_actions": "voice · email · slack · shell (nada detectado)",
    "customer_data": "UPDATE/DELETE users/customers/orders",
    "llm": "anthropic · openai (nada detectado)",
    "general": "http routes · cron schedules · informativo",
}


def _tier_hint(tier: str, items: list, summary) -> str:
    """Repo-specific one-line hint for what each tier actually found here.

    Prefer real providers from the summary (e.g. 'twilio, elevenlabs') over
    the generic fallback. Keeps the terminal output accurate to THIS repo."""
    if tier == "money" and summary.payment_integrations:
        parts: list[str] = []
        for vendor, caps in summary.payment_integrations.items():
            parts.append(f"{vendor} ({', '.join(caps)})" if caps else vendor)
        return ", ".join(parts)[:60]

    if tier == "real_world_actions" and summary.real_world_actions:
        # One capability → "voice (twilio, elevenlabs)". Many → first 2 capabilities.
        entries = list(summary.real_world_actions.items())
        parts = [f"{cap.split(' ')[0]} ({', '.join(providers)})" for cap, providers in entries[:2]]
        more = f" +{len(entries) - 2}" if len(entries) > 2 else ""
        return ", ".join(parts)[:55] + more

    if tier == "llm" and summary.llm_providers:
        return ", ".join(summary.llm_providers)[:60]

    if tier == "customer_data":
        if summary.sensitive_tables:
            sample = ", ".join(summary.sensitive_tables[:4])
            more = f" +{len(summary.sensitive_tables) - 4}" if len(summary.sensitive_tables) > 4 else ""
            return f"tablas: {sample}{more}"[:60]
        return _TIER_FALLBACK[tier]

    if tier == "general":
        bits: list[str] = []
        if summary.http_routes:
            bits.append(f"{summary.http_routes} routes")
        if summary.scheduled_jobs:
            bits.append(f"{summary.scheduled_jobs} crons")
        return " · ".join(bits) if bits else _TIER_FALLBACK[tier]

    return _TIER_FALLBACK.get(tier, "")


def _print_tier_summary(root: Path, findings: list, elapsed: float, out: Path) -> None:
    """Repo summary + tier-by-risk on stderr, with a repo-specific hint
    column so a vibe coder reading this for the first time understands WHAT
    each tier actually means in their codebase."""
    buckets = group_by_risk_tier(findings)
    summary = build_summary(findings)

    print(f"scanned {root} in {elapsed:.1f}s", file=sys.stderr)
    print("", file=sys.stderr)
    for line in render_cli_stdout(summary):
        print(line, file=sys.stderr)
    print("", file=sys.stderr)

    # Column layout: title (22) · counts (24) · hint (flex)
    for tier in TIER_ORDER:
        items = buckets[tier]
        title = TIER_COPY[tier]["title"]
        hint = _tier_hint(tier, items, summary)

        if tier == "general":
            counts = f"{len(items)} informational"
        else:
            high = sum(1 for f in items if f.confidence == "high")
            med = sum(1 for f in items if f.confidence == "medium")
            low = sum(1 for f in items if f.confidence == "low")
            counts = f"{high} high / {med} medium / {low} low"

        print(f"  {title:<22s}  {counts:<24s}  {hint}", file=sys.stderr)

    print("", file=sys.stderr)
    print(f"-> wrote {out}", file=sys.stderr)
    print(f"-> next: open {out / 'SUMMARY.md'} — security review priorizada (lo que harías hoy, mañana, día 4)", file=sys.stderr)
    print(f"   or:   {out / 'ROLLOUT.md'} para el deploy playbook por fases", file=sys.stderr)


def _handle_fix(args: argparse.Namespace) -> int:
    """Nivel 2 stub — just explains what this command would do + points at
    the markdown playbook that covers the same combo today."""
    from .combo_autofix import AutofixNotImplemented, apply, explain

    out = Path(args.out).resolve()
    playbook = out / "combos" / f"{args.combo_id}.md"

    print(explain(), file=sys.stderr)
    print("", file=sys.stderr)

    if playbook.exists():
        print(f"Nivel 1 playbook (active, manual) disponible en:", file=sys.stderr)
        print(f"  {playbook}", file=sys.stderr)
        print("", file=sys.stderr)
        print("Ábrelo y sigue los pasos copy-paste. Cuando Nivel 2 shippee,", file=sys.stderr)
        print("este mismo comando lo aplicará automáticamente con --experimental.", file=sys.stderr)
    else:
        print(f"No existe playbook para '{args.combo_id}'. Corre `supervisor-discover scan`", file=sys.stderr)
        print("primero para generar el directorio runtime-supervisor/combos/.", file=sys.stderr)
        return 2

    # If user passed --experimental, still reject — the impl isn't ready.
    if args.experimental:
        try:
            apply(args.combo_id, out, experimental=True)
        except AutofixNotImplemented as exc:
            print("", file=sys.stderr)
            print(str(exc), file=sys.stderr)
            return 2
    return 0


def _handle_combos(args: argparse.Namespace) -> int:
    """Nivel 3 — gestiona el estado de los combos detectados.

    Verbos:
      list (default)   — muestra estado de cada combo
      resolve <id>     — marca resolved (se suprime del próximo scan)
      in-progress <id> — marca en progreso (sigue reportándose con nota)
      reopen <id>      — vuelve a open
      clear            — borra el state file
    """
    from .combo_state import (
        clear as clear_state,
        load as load_state,
        mark_in_progress,
        mark_open,
        mark_resolved,
        state_path_for,
    )

    out_dir = Path(args.out).resolve()
    state_path = state_path_for(out_dir)
    verb = getattr(args, "combos_verb", None) or "list"

    if verb == "list":
        states = load_state(state_path)
        if not states:
            print(f"Sin state file en {state_path}.", file=sys.stderr)
            print("Corre `supervisor-discover scan` primero, después marca combos con", file=sys.stderr)
            print("  supervisor-discover combos resolve <combo-id>", file=sys.stderr)
            return 0
        print(f"Estado en {state_path}:", file=sys.stderr)
        print("", file=sys.stderr)
        emoji = {"open": "🟠", "in-progress": "🟡", "resolved": "✅"}
        for cid in sorted(states.keys()):
            s = states[cid]
            print(f"  {emoji.get(s.status, '•')} {s.status:<12s} {cid}", file=sys.stderr)
            if s.note:
                print(f"       _{s.note}_", file=sys.stderr)
            if s.resolved_at:
                who = f" por {s.resolved_by}" if s.resolved_by else ""
                print(f"       resuelto {s.resolved_at}{who}", file=sys.stderr)
        return 0

    if verb == "resolve":
        state = mark_resolved(args.combo_id, state_path, by=args.by, note=args.note)
        print(f"✅ combo `{args.combo_id}` marcado como resolved.", file=sys.stderr)
        print(f"   State: {state_path}", file=sys.stderr)
        print(f"   El próximo `supervisor-discover scan` no lo va a reportar.", file=sys.stderr)
        print(f"   Para revertir: supervisor-discover combos reopen {args.combo_id}", file=sys.stderr)
        return 0

    if verb == "in-progress":
        mark_in_progress(args.combo_id, state_path, note=args.note)
        print(f"🟡 combo `{args.combo_id}` marcado como in-progress.", file=sys.stderr)
        print(f"   Sigue apareciendo en scans — resolvelo con `combos resolve` cuando apliques el playbook.", file=sys.stderr)
        return 0

    if verb == "reopen":
        mark_open(args.combo_id, state_path)
        print(f"🟠 combo `{args.combo_id}` vuelto a open.", file=sys.stderr)
        print(f"   Va a reaparecer en el próximo scan.", file=sys.stderr)
        return 0

    if verb == "clear":
        if clear_state(state_path):
            print(f"State file {state_path} borrado.", file=sys.stderr)
            print("Todos los combos vuelven a reportarse en el próximo scan.", file=sys.stderr)
        else:
            print(f"No había state file en {state_path}.", file=sys.stderr)
        return 0

    print(f"error: verbo desconocido '{verb}'", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
