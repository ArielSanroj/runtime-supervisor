"""Public scan redaction. Submitter holds a one-time access token from
POST /v1/scans; without that token the GET response strips file paths,
line numbers, and code snippets so anonymous callers can't use the public
scanner as a free recon tool against arbitrary public repos.

The redaction is structural — same response shape, scrubbed values — so
the existing UI keeps rendering. The token is constant-time-compared, so
the secret value is not leakable through timing attacks."""
from __future__ import annotations

from supervisor_api.routes.scans import (
    _check_access_token,
    _redact_combos,
    _redact_findings,
    _redact_payload,
    _redact_repo_summary,
)


def _payload() -> dict:
    return {
        "scan_id": "abc",
        "status": "done",
        "github_url": "https://github.com/owner/repo",
        "access_token": "tok-secret",
        "findings": [
            {
                "scanner": "fs-shell",
                "file": "/repo/src/x.py",
                "line": 42,
                "snippet": "subprocess.Popen(cmd)",
                "suggested_action_type": "tool_use",
                "confidence": "high",
                "rationale": "shell exec",
                "extra": {"family": "shell-exec"},
                "tier": "real_world_actions",
            },
        ],
        "combos": [
            {
                "id": "llm-plus-shell-exec",
                "title": "LLM + shell exec",
                "severity": "critical",
                "narrative": "co-occurrence",
                "evidence": ["src/x.py:42", "src/y.py:10"],
                "mitigation": "wrap with @supervised",
            },
        ],
        "repo_summary": {
            "frameworks": ["Flask"],
            "agent_chokepoints": [
                {"file": "/repo/src/agent.py", "line": 1, "kind": "agent-class",
                 "label": "MyAgent", "parallel_methods": []},
            ],
            "start_here": {
                "top_wrap_targets": [
                    {"label": "MyAgent", "file": "/repo/src/agent.py",
                     "line": 1, "why": "central dispatcher", "parallel_methods": []},
                ],
                "framework_signals": [
                    {"framework": "langchain", "file": "/repo/src/x.py",
                     "line": 5, "snippet": "from langchain import ..."},
                ],
                "top_risks": [
                    {"title": "Shell execution present",
                     "confirmed_in_code": "subprocess.Popen at src/x.py:42",
                     "possible_chain": "...", "do_this_now": "wrap",
                     "family": "fs-shell", "example": "```py\n# src/x.py:42\n```"},
                ],
                "do_this_now": "Wrap MyAgent.dispatch in src/agent.py:1",
                "bootstrap": {
                    "manager": {"kind": "uv", "language": "python",
                                "manifest_path": "/repo/pyproject.toml",
                                "install_cmd": "uv add ..."},
                    "entrypoint": {"file": "/repo/app.py", "line": 1,
                                   "framework": "flask", "language": "python"},
                    "configure_already_called": False,
                },
            },
        },
    }


# ─── _check_access_token ──────────────────────────────────────────


def test_check_access_token_match():
    assert _check_access_token({"access_token": "tok-secret"}, "tok-secret") is True


def test_check_access_token_mismatch():
    assert _check_access_token({"access_token": "tok-secret"}, "tok-wrong") is False


def test_check_access_token_missing_persisted():
    """A scan with no persisted token never authorizes — that handles legacy
    rows from before the token feature shipped (they get permanent redaction)."""
    assert _check_access_token({}, "anything") is False


def test_check_access_token_missing_provided():
    """Anonymous callers (no token in URL/header) never authorize."""
    assert _check_access_token({"access_token": "tok"}, None) is False


def test_check_access_token_empty_provided():
    """Empty string is treated as missing — guards against `?access_token=`
    in the URL with no value."""
    assert _check_access_token({"access_token": "tok"}, "") is False


# ─── _redact_findings ─────────────────────────────────────────────


def test_redact_findings_strips_file_line_snippet():
    findings = _payload()["findings"]
    out = _redact_findings(findings)
    assert out[0]["file"].startswith("[hidden")
    assert out[0]["line"] == 0
    assert out[0]["snippet"] == "[hidden]"
    # Counts and categories survive — that's the whole point.
    assert out[0]["scanner"] == "fs-shell"
    assert out[0]["confidence"] == "high"
    assert out[0]["tier"] == "real_world_actions"
    assert out[0]["suggested_action_type"] == "tool_use"


def test_redact_findings_strips_extra_dict():
    """The extra dict can carry class names and other repo-specific
    identifiers that count as recon. Strip wholesale rather than try to
    enumerate which keys are safe."""
    findings = _payload()["findings"]
    out = _redact_findings(findings)
    assert out[0]["extra"] == {}


def test_redact_findings_does_not_mutate_input():
    """Defensive: the redactor must not mutate the persisted blob.
    Otherwise a single redacted GET would poison the cached payload for
    everyone, including the legitimate token holder."""
    findings = _payload()["findings"]
    snapshot_file = findings[0]["file"]
    _redact_findings(findings)
    assert findings[0]["file"] == snapshot_file


# ─── _redact_repo_summary ─────────────────────────────────────────


def test_redact_summary_strips_chokepoint_labels_and_paths():
    summary = _payload()["repo_summary"]
    out = _redact_repo_summary(summary)
    cps = out["agent_chokepoints"]
    assert cps[0]["file"].startswith("[hidden")
    assert cps[0]["label"] == "[hidden]"
    assert cps[0]["line"] == 0
    # `kind` survives so the UI can still say "1 agent-class detected".
    assert cps[0]["kind"] == "agent-class"


def test_redact_summary_strips_start_here_targets():
    summary = _payload()["repo_summary"]
    out = _redact_repo_summary(summary)
    sh = out["start_here"]
    tgt = sh["top_wrap_targets"][0]
    assert tgt["file"].startswith("[hidden")
    assert tgt["label"] == "[hidden]"
    assert tgt["line"] == 0


def test_redact_summary_strips_framework_signal_paths():
    """Framework signals expose `from langchain import …` at file:line —
    that's enough to reconstruct module structure. Strip the path."""
    summary = _payload()["repo_summary"]
    out = _redact_repo_summary(summary)
    sig = out["start_here"]["framework_signals"][0]
    assert sig["file"].startswith("[hidden")
    assert sig["line"] == 0
    # `framework` survives — knowing langchain is in use is fine.
    assert sig["framework"] == "langchain"


def test_redact_summary_replaces_do_this_now_with_unlock_cta():
    """do_this_now embeds file:line in the markdown body. Replace
    wholesale with copy that points at the unlock path."""
    summary = _payload()["repo_summary"]
    out = _redact_repo_summary(summary)
    do_now = out["start_here"]["do_this_now"]
    assert "src/agent.py" not in do_now
    assert "MyAgent" not in do_now
    assert "claim" in do_now.lower() or "sign in" in do_now.lower()


def test_redact_summary_strips_bootstrap_paths():
    summary = _payload()["repo_summary"]
    out = _redact_repo_summary(summary)
    bs = out["start_here"]["bootstrap"]
    assert bs["entrypoint"]["file"].startswith("[hidden")
    assert bs["entrypoint"]["line"] == 0
    assert bs["manager"]["manifest_path"].startswith("[hidden")
    # Manager kind / install_cmd survive — they're public package info.
    assert bs["manager"]["kind"] == "uv"


def test_redact_summary_keeps_frameworks_and_capabilities():
    """Counters / lists with no path info pass through unchanged. The
    point of redaction is to hide *where* — not *whether*."""
    summary = _payload()["repo_summary"]
    out = _redact_repo_summary(summary)
    assert out["frameworks"] == ["Flask"]


# ─── _redact_combos ───────────────────────────────────────────────


def test_redact_combos_strips_evidence():
    combos = _payload()["combos"]
    out = _redact_combos(combos)
    assert out[0]["evidence"] == []
    # title / severity / narrative / mitigation survive.
    assert out[0]["severity"] == "critical"
    assert out[0]["title"] == "LLM + shell exec"
    assert out[0]["narrative"] == "co-occurrence"


# ─── _redact_payload (top-level) ──────────────────────────────────


def test_redact_payload_marks_redacted_true():
    out = _redact_payload(_payload())
    assert out["redacted"] is True


def test_redact_payload_strips_access_token():
    """The persisted blob carries the token; the GET response must NEVER
    return it to anonymous callers — that would be a one-shot
    bypass of the gate."""
    out = _redact_payload(_payload())
    assert "access_token" not in out


def test_redact_payload_does_not_mutate_input():
    payload = _payload()
    snapshot_token = payload["access_token"]
    _redact_payload(payload)
    assert payload["access_token"] == snapshot_token
    assert payload["findings"][0]["file"].startswith("/repo/")
