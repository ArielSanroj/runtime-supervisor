"""Tests for reachability classification + walker noise filters + HTTP verb.

These guard against the three trust-breakers reported on real repos:
  - GiftedAgentV2: `langchain_NR_setup.py` (test/setup script) headlining
    "Best place to wrap first".
  - castor-1:     bundles like `5566.c76ea61eb723ee84e2cf.js` flagged as
    findings; SKILL.md files surfaced as "Gate N call-sites".
  - GiftedAgentV2: a GET fetch on `…/calendar/v3/.../events` flagged as a
    calendar mutation.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from supervisor_discover.scanners._utils import (
    _is_bundle_artifact,
    detect_http_verb_near,
)
from supervisor_discover.scanners.agent_orchestrators import (
    _custom_orch_findings,
    _is_custom_orchestrator_file,
)
from supervisor_discover.summary import is_low_reachability_path
from supervisor_discover.templates import (
    py_payload_body_for,
    ts_payload_body_for,
)


# Reachability classifier --------------------------------------------

@pytest.mark.parametrize("path", [
    "tests/foo.py",
    "src/legacy/orch.py",
    "scripts/deploy.py",
    "test-setup-newrelic/langchain_NR_setup.py",
    "backend/setup.py",
    "src/__tests__/agent.spec.ts",
    "examples/demo_agent.py",
])
def test_low_reachability_paths_classified_as_unreachable(path: str):
    assert is_low_reachability_path(path)


@pytest.mark.parametrize("path", [
    "src/agents/orchestrator.py",
    "supabase/functions/orchestrator/index.ts",
    "backend/services/agent/electoral_intelligence_agent.py",
    "api/routes/payments.py",
    "src/index.ts",
])
def test_production_paths_classified_as_reachable(path: str):
    assert not is_low_reachability_path(path)


# Bundle / noise file filter ----------------------------------------

@pytest.mark.parametrize("name", [
    "5566.c76ea61eb723ee84e2cf.js",
    "main.a1b2c3d4e5f6.js",
    "vendor.bundle.js",
    "app.min.js",
    "main.chunk.js",
    "bundle.js.map",
    "styles.abc12345.css",
])
def test_bundle_artifacts_skipped(name: str):
    assert _is_bundle_artifact(Path(name))


@pytest.mark.parametrize("name", [
    "index.ts",
    "agent.py",
    "calendar.ts",
    "main.py",
    # 4-char hex is below the 8-char threshold — likely a real filename, not a hash.
    "v1.dead.js",
])
def test_real_source_not_skipped(name: str):
    assert not _is_bundle_artifact(Path(name))


# HTTP verb sniffing ------------------------------------------------

def test_http_verb_plain_fetch_defaults_to_read():
    """`fetch(url, { headers })` with no `method:` key → default GET. The
    sniffer must classify as READ so the calendar-actions scanner skips this
    finding (the GiftedAgentV2 false-positive at calendar.ts:140)."""
    text = """
const url = `https://www.googleapis.com/calendar/v3/calendars/${id}/events?timeMin=${a}`;
let res = await fetch(url, { headers: { Authorization: `Bearer ${tok}` } });
"""
    pos = text.find("googleapis")
    assert detect_http_verb_near(text, pos) == "READ"


def test_http_verb_truly_ambiguous_returns_none():
    """No fetch / requests / method key in the window → really ambiguous."""
    text = """
const url = "https://api.x.com/v1/items";
log.info("loaded", url);
"""
    pos = text.find("api.x.com")
    assert detect_http_verb_near(text, pos) is None


def test_http_verb_explicit_method_post_classifies_as_write():
    text = """
const res = await fetch(
  `https://www.googleapis.com/calendar/v3/calendars/${id}/events`,
  { method: "POST", headers: {}, body: JSON.stringify(event) },
);
"""
    pos = text.find("googleapis")
    assert detect_http_verb_near(text, pos) == "WRITE"


def test_http_verb_explicit_method_get_classifies_as_read():
    text = """
const res = await fetch(`https://api.x.com/v1/items`, { method: "GET" });
"""
    pos = text.find("api.x.com")
    assert detect_http_verb_near(text, pos) == "READ"


def test_http_verb_requests_post_classifies_as_write():
    text = """
import requests
r = requests.post("https://api.cal.com/v2/bookings", json={"slot": s})
"""
    pos = text.find("api.cal.com")
    assert detect_http_verb_near(text, pos) == "WRITE"


# Custom orchestrator detection ------------------------------------

@pytest.mark.parametrize("path", [
    "supabase/functions/orchestrator/index.ts",
    "supabase/functions/orchestrator/router.ts",
    "src/dispatcher/main.py",
    "src/coordinator/coordinator.py",
    "services/orchestrator.py",
])
def test_custom_orchestrator_file_detected_by_path(path: str):
    assert _is_custom_orchestrator_file(path)


@pytest.mark.parametrize("path", [
    "src/api/routes/payments.py",
    "src/components/Button.tsx",
    "src/utils/log.ts",
])
def test_non_orchestrator_files_rejected(path: str):
    assert not _is_custom_orchestrator_file(path)


def test_custom_orchestrator_emits_chokepoint_for_a2a_pattern(tmp_path: Path):
    """The GiftedAgentV2 A2A pattern: registry.register({...}) +
    registry.execute(...) in supabase/functions/orchestrator/index.ts. Must
    surface as an agent-class chokepoint even with no LangChain import."""
    src_dir = tmp_path / "supabase" / "functions" / "orchestrator"
    src_dir.mkdir(parents=True)
    (src_dir / "index.ts").write_text("""
import { registry } from "./registry.ts";

registry.register({
  name: "task-agent",
  intents: ["create_task"],
  handler: handleTask,
});

export async function handleRequest(c: Context) {
  const result = await registry.execute(classified.agent, { intent, params });
  return c.json(result);
}
""")
    findings = _custom_orch_findings(src_dir / "index.ts",
                                     (src_dir / "index.ts").read_text())
    assert len(findings) == 1
    assert findings[0].extra.get("kind") == "agent-class"
    assert findings[0].extra.get("pattern") == "custom-orchestrator"
    assert findings[0].confidence == "high"


def test_custom_orchestrator_silent_on_path_match_without_dispatch(tmp_path: Path):
    """A file in /orchestrator/ with no dispatch pattern must NOT emit —
    path alone is too noisy."""
    src_dir = tmp_path / "src" / "orchestrator"
    src_dir.mkdir(parents=True)
    (src_dir / "types.ts").write_text("export interface Agent { name: string; }")
    findings = _custom_orch_findings(src_dir / "types.ts",
                                     (src_dir / "types.ts").read_text())
    assert findings == []


# Stub payload extractors -----------------------------------------

@pytest.mark.parametrize("scanner,fields", [
    ("payment-calls", ["amount", "currency", "customer_id", "reason"]),
    ("fs-shell", ["command", "args", "cwd"]),
    ("email-sends", ["to", "subject", "recipient_count"]),
    ("messaging", ["channel", "recipient", "body"]),
    ("voice-actions", ["to_number", "from_number", "voice_id"]),
    ("calendar-actions", ["calendar_id", "summary", "attendees"]),
    ("llm-calls", ["model", "messages", "tools", "prompt_length"]),
    ("db-mutations", ["sql", "params"]),
])
def test_py_payload_body_lists_policy_fields(scanner: str, fields: list[str]):
    """Each scanner-specific Python payload body must reference the fields
    the policy `when:` clauses actually expect — without these the stub is
    indistinguishable from a generic one and the dev has to guess."""
    body = py_payload_body_for(scanner)
    for field in fields:
        assert field in body, f"missing {field!r} in {scanner} payload body"


def test_py_payload_body_falls_back_for_unknown_scanner():
    body = py_payload_body_for("nonexistent-scanner")
    assert "raw_args" in body and "raw_kwargs" in body


@pytest.mark.parametrize("scanner,fields", [
    ("payment-calls", ["amount", "currency", "customer_id"]),
    ("calendar-actions", ["calendar_id", "summary", "attendees"]),
    ("llm-calls", ["model", "messages", "tools"]),
])
def test_ts_payload_body_lists_policy_fields(scanner: str, fields: list[str]):
    body = ts_payload_body_for(scanner)
    for field in fields:
        assert field in body
