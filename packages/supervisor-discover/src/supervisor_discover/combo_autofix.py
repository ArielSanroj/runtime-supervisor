"""Nivel 2 (opt-in): auto-apply combo playbooks — STUB.

Planned behavior: `ac fix <combo-id>` (or `supervisor-discover fix <combo-id>`)
reads the generated playbook, applies the policy YAML via the supervisor API,
edits the user's source files to wrap the call-sites, and runs the verification
test — returning a diff for review.

Why stubbed: touching user source code is high-blast-radius. We want the
deterministic playbook (Nivel 1) to be the default until (a) we have robust
stub-to-source patching, (b) we have rollback/undo, and (c) we've proven the
patches don't break anything on 20+ real repos.

To enable when ready:
  1. Implement `apply(combo_id, out_dir)` below.
  2. Wire the CLI subcommand in `cli.py`.
  3. Require `--experimental` flag so users opt-in explicitly.

Track the design in github.com/ArielSanroj/runtime-supervisor/issues/AUTOFIX.
"""

from __future__ import annotations

from pathlib import Path


class AutofixNotImplemented(Exception):
    """Raised when `apply()` is called — until the feature ships."""


def apply(combo_id: str, out_dir: Path, *, experimental: bool = False) -> None:
    """Apply the playbook for `combo_id`. Not yet implemented."""
    raise AutofixNotImplemented(
        f"Auto-fix is Nivel 2 (opt-in) and not yet implemented. "
        f"Open runtime-supervisor/combos/{combo_id}.md and apply the steps manually. "
        f"Want this to ship sooner? Track it in github.com/ArielSanroj/runtime-supervisor."
    )


def explain() -> str:
    """Describe Nivel 2 to the user (printed by `ac fix --help` in the future)."""
    return (
        "Nivel 2 — auto-fix\n"
        "==================\n"
        "Aplica el playbook de un combo automáticamente: promueve la policy,\n"
        "edita los call-sites, corre el test de verificación. High-blast-radius,\n"
        "requiere --experimental flag una vez implementado.\n"
        "\n"
        "Estado actual: stub. Usar Nivel 1 (playbook manual) por ahora."
    )
