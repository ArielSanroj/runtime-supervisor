"""Detect call-sites that disable transport / auth security checks.

Two attack shapes:

1. **TLS verification disabled** — `requests.get(url, verify=False)` /
   `httpx.get(url, verify=False)` / `aiohttp.ClientSession(connector=...,
   verify_ssl=False)`. Any HTTPS call after this is no longer verified;
   a man-in-the-middle (intentional or accidental — wrong certs, dev cert
   leaking to prod) silently succeeds. Medium confidence because some
   internal-only repos legitimately disable verification on non-secret
   endpoints, but it's worth flagging at every call-site.

2. **JWT signature skipped** — `jwt.decode(token, key, options={
   "verify_signature": False})` / `jwt.decode(..., verify=False)` (PyJWT
   <2.0 syntax) / `jwt.decode(..., algorithms=["none"])`. All three
   accept any token as valid — auth bypass with no decoder error. High
   confidence because there's no benign use case in production.

The scanner is AST-based for Python (immune to matches in comments and
strings) and regex for TS/JS. It emits findings with the new families
`tls-bypass` and `jwt-bypass` so START_HERE / FULL_REPORT can route them
to dedicated risk cards.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from ..findings import Finding
from ._utils import dotted_name, parse_python, python_files, safe_read, ts_js_files


# Python call targets where a `verify=False` kwarg disables TLS verification.
# Resolved via AST so `requests.get` and `client.get` (with `client` bound to
# `requests.Session()`) both surface — for the bound case we still see the
# `.get(...)` attribute, which we treat as a candidate AND require the
# `verify=False` kwarg before emitting.
_TLS_TARGETS_BY_NAME = frozenset({
    "requests.get", "requests.post", "requests.put", "requests.patch",
    "requests.delete", "requests.head", "requests.request",
    "httpx.get", "httpx.post", "httpx.put", "httpx.patch", "httpx.delete",
    "httpx.head", "httpx.request", "httpx.stream",
    "httpx.Client", "httpx.AsyncClient",
    "requests.Session",
    # urllib3 / aiohttp variants — keep narrow because false positives
    # outweigh the marginal coverage gain. Add as users surface them.
})

# Method-suffix matches for bound clients (`session.post(...)` where session
# was created earlier as `requests.Session()`).
_TLS_BOUND_METHODS = frozenset({
    "get", "post", "put", "patch", "delete", "head", "request", "stream",
})

# JWT decode patterns — just the function names. Module names vary
# (PyJWT, python-jose, jose.jwt). We match the suffix `.decode` and require a
# kwargs check before flagging.
_JWT_DECODE_SUFFIXES = ("jwt.decode", "jose.jwt.decode", "jose.jws.verify")


# JS/TS regex — narrower than Python because no AST. We match the literal
# token sequence `verify: false` / `verifySsl: false` in axios / fetch
# config objects, plus jwt verify=false / algorithms: ["none"].
_JS_TLS_BYPASS = re.compile(
    r"\b(?:rejectUnauthorized|verify|verifySsl|verify_ssl)\s*:\s*false\b",
    re.IGNORECASE,
)
_JS_JWT_BYPASS = re.compile(
    r"\bjwt\.(?:verify|decode)\s*\([^)]*?(?:verify\s*:\s*false|"
    r"algorithms\s*:\s*\[\s*['\"]none['\"]\s*\])",
    re.IGNORECASE | re.DOTALL,
)


_RATIONALES = {
    "tls-bypass": (
        "TLS verification disabled — the call accepts any certificate, "
        "including self-signed or attacker-presented ones. A network-level "
        "attacker (rogue Wi-Fi, intercepted CI runner, mistakenly imported "
        "dev cert) becomes a silent man-in-the-middle. Gate with "
        "@supervised('tool_use') and pin a CA bundle for the destination."
    ),
    "jwt-bypass": (
        "JWT signature check disabled — the decoder accepts any token, "
        "even one the attacker forged with a different key (or the empty "
        "key when `algorithms=['none']`). Effectively turns every "
        "downstream `if user_role == 'admin'` into a free-for-all. Remove "
        "the bypass; if the token is genuinely untrusted, reject it instead "
        "of decoding it without verification."
    ),
}


# ─── Python AST path ───────────────────────────────────────────────────


def _kwarg_is_false(node: ast.Call, name: str) -> bool:
    """True when `node` has a kwarg named `name` whose value is the literal
    `False`. (Variables that happen to be False at runtime don't count —
    we want explicit, statically-visible bypasses.)"""
    for kw in node.keywords:
        if kw.arg != name:
            continue
        if isinstance(kw.value, ast.Constant) and kw.value.value is False:
            return True
    return False


def _has_options_verify_false(node: ast.Call) -> bool:
    """Match the PyJWT 2.x style: `jwt.decode(..., options={"verify_signature": False})`."""
    for kw in node.keywords:
        if kw.arg != "options":
            continue
        opts = kw.value
        if not isinstance(opts, ast.Dict):
            continue
        for key, value in zip(opts.keys, opts.values):
            if not isinstance(key, ast.Constant) or key.value != "verify_signature":
                continue
            if isinstance(value, ast.Constant) and value.value is False:
                return True
    return False


def _has_algorithms_none(node: ast.Call) -> bool:
    """Match `jwt.decode(..., algorithms=["none"])` — an explicit none-alg
    accept."""
    for kw in node.keywords:
        if kw.arg != "algorithms":
            continue
        v = kw.value
        if isinstance(v, ast.List):
            for elt in v.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    if elt.value.lower() == "none":
                        return True
    return False


def _matches_jwt_decode(name: str | None) -> bool:
    if not name:
        return False
    return any(name.endswith(suffix) or name == suffix.split(".")[-1] for suffix in (
        "jwt.decode", "jose.jwt.decode", "jose.jws.verify",
    )) or name == "decode"


def _scan_python(path: Path, text: str) -> list[Finding]:
    tree = parse_python(text)
    if tree is None:
        return []
    source_lines = text.splitlines()
    out: list[Finding] = []

    # Track names bound to TLS-capable clients so we can flag bound-method
    # calls. `client = requests.Session()` → `client.get(..., verify=False)`
    # should surface. We don't follow flow across functions; a single-pass
    # scan with module-scope assignments is enough for the common case.
    bound_clients: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            value = node.value
            if isinstance(value, ast.Call):
                callee = dotted_name(value.func)
                if callee in {"requests.Session", "httpx.Client", "httpx.AsyncClient"}:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            bound_clients.add(target.id)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # ── TLS bypass ─────────────────────────────────────────────────
        callee_name = dotted_name(node.func)
        is_tls_call = False
        if callee_name in _TLS_TARGETS_BY_NAME:
            is_tls_call = True
        elif (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in _TLS_BOUND_METHODS
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in bound_clients
        ):
            is_tls_call = True

        if is_tls_call and _kwarg_is_false(node, "verify"):
            line = node.lineno
            snippet = (source_lines[line - 1].strip()[:80]
                       if 0 <= line - 1 < len(source_lines) else "verify=False")
            out.append(Finding(
                scanner="auth-bypass",
                file=str(path),
                line=line,
                snippet=snippet,
                suggested_action_type="tool_use",
                confidence="medium",
                rationale=_RATIONALES["tls-bypass"],
                extra={"family": "tls-bypass", "label": callee_name or node.func.attr},
            ))
            continue  # one finding per call

        # ── JWT bypass ─────────────────────────────────────────────────
        if _matches_jwt_decode(callee_name):
            triggered = (
                _kwarg_is_false(node, "verify")
                or _has_options_verify_false(node)
                or _has_algorithms_none(node)
            )
            if triggered:
                line = node.lineno
                snippet = (source_lines[line - 1].strip()[:80]
                           if 0 <= line - 1 < len(source_lines) else "jwt.decode(...)")
                out.append(Finding(
                    scanner="auth-bypass",
                    file=str(path),
                    line=line,
                    snippet=snippet,
                    suggested_action_type="tool_use",
                    confidence="high",
                    rationale=_RATIONALES["jwt-bypass"],
                    extra={"family": "jwt-bypass", "label": callee_name or "jwt.decode"},
                ))
    return out


# ─── JS/TS regex path ──────────────────────────────────────────────────


def _scan_js(path: Path, text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in _JS_TLS_BYPASS.finditer(text):
        line = text[: m.start()].count("\n") + 1
        out.append(Finding(
            scanner="auth-bypass",
            file=str(path),
            line=line,
            snippet=m.group(0)[:80],
            suggested_action_type="tool_use",
            confidence="medium",
            rationale=_RATIONALES["tls-bypass"],
            extra={"family": "tls-bypass", "label": m.group(0)},
        ))
    for m in _JS_JWT_BYPASS.finditer(text):
        line = text[: m.start()].count("\n") + 1
        out.append(Finding(
            scanner="auth-bypass",
            file=str(path),
            line=line,
            snippet=m.group(0)[:80].replace("\n", " "),
            suggested_action_type="tool_use",
            confidence="high",
            rationale=_RATIONALES["jwt-bypass"],
            extra={"family": "jwt-bypass", "label": "jwt.decode"},
        ))
    return out


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in python_files(root):
        text = safe_read(path)
        if text is None:
            continue
        findings.extend(_scan_python(path, text))
    for path in ts_js_files(root):
        text = safe_read(path)
        if text is None:
            continue
        findings.extend(_scan_js(path, text))
    return findings
