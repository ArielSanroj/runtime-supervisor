"""Track Python import aliases.

Resolves `import stripe as _stripe` → {"_stripe": "stripe"} and
`from openai import OpenAI` → {"OpenAI": "openai.OpenAI"}. The
per-file alias map lets other scanners answer "is this call on a
stripe / openai / anthropic module?" instead of relying on fragile
substring matches on method names.
"""
from __future__ import annotations

import ast


def build_alias_map(tree: ast.AST) -> dict[str, str]:
    """Returns {local_name: canonical_dotted_path} for every import seen."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                local = a.asname or a.name.split(".")[0]
                aliases[local] = a.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                local = a.asname or a.name
                aliases[local] = f"{node.module}.{a.name}"
    return aliases


def resolve_call_name(node: ast.Call, aliases: dict[str, str]) -> str:
    """Turn an ast.Call into a dotted string with the root expanded to its
    imported canonical name. E.g., for `_stripe.Refund.create(...)` with
    aliases {_stripe: stripe}, returns "stripe.Refund.create".
    """
    fn = node.func
    parts: list[str] = []
    while isinstance(fn, ast.Attribute):
        parts.append(fn.attr)
        fn = fn.value
    if isinstance(fn, ast.Name):
        root = fn.id
        parts.append(aliases.get(root, root))
    return ".".join(reversed(parts))


def root_module(dotted: str) -> str:
    return dotted.split(".")[0]
