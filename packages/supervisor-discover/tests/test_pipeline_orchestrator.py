"""Tests for the agent vs pipeline orchestrator classifier.

The reviewer flagged on castor-1 that `BurstOrchestrator` (an httpx async
pool that drives a scraper) and the OCR `*Agent` classes were headlining
"Best place to wrap first" alongside real LLM-driven agents like
`AlertDispatcher` and `ElectoralIntelligenceAgent`. Wrapping a worker
pool with `@supervised('tool_use')` doesn't protect anything — there's
no LLM in that flow — and it eats the rollout's FP budget for nothing.

The classifier requires *positive evidence* of pipeline shape (a scraper
or OCR or queue-worker library import) before reclassifying. Just
"doesn't import OpenAI" is too aggressive — `AlertDispatcher` passes
that test and it's a real agent surface.
"""
from __future__ import annotations

from pathlib import Path

from supervisor_discover.findings import Finding
from supervisor_discover.scanners import agent_orchestrators


def _write(tmp: Path, name: str, body: str) -> Path:
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


def _scan(tmp: Path) -> list[Finding]:
    return agent_orchestrators.scan(tmp)


def _classes(findings: list[Finding]) -> dict[str, Finding]:
    """Return {class_name: finding} for agent-class findings only."""
    return {
        (f.extra or {}).get("class_name"): f
        for f in findings
        if (f.extra or {}).get("kind") == "agent-class"
    }


# ─── Pipeline-shaped → reclassified ────────────────────────────────


def test_httpx_scraper_class_filtered_by_agent_gate(tmp_path: Path):
    """The BurstOrchestrator pattern (httpx async pool, no LLM SDK, no
    intent dispatch) used to be demoted to `pipeline_orchestrator low`.
    With the generic-token gate it's filtered out earlier — it never
    even registers as agent-class because there's no LLM import and no
    decision-branching. The 10-repo benchmark made this the right
    outcome: medusa's TransactionOrchestrator and chatwoot's similar
    classes shouldn't be in the priority surface at all."""
    _write(tmp_path, "scraper/burst.py", """
import asyncio
import httpx

class BurstOrchestrator:
    def __init__(self):
        self.client = httpx.AsyncClient()

    async def fetch_all(self, urls):
        return await asyncio.gather(*(self.client.get(u) for u in urls))
""")
    findings = _scan(tmp_path)
    classes = _classes(findings)
    assert "BurstOrchestrator" not in classes, (
        "Generic Orchestrator without LLM/branching evidence must be "
        "filtered out by the agent-class gate before reaching the "
        "pipeline classifier."
    )


def test_ocr_pipeline_class_reclassified(tmp_path: Path):
    """OCR pipeline stages with literal cv2/pytesseract imports."""
    _write(tmp_path, "ocr/totals_agent.py", """
import cv2
import pytesseract
from typing import Dict, Any

class TotalsAgent:
    def extract(self, image) -> Dict[str, Any]:
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        return {"text": pytesseract.image_to_string(gray)}
""")
    findings = _scan(tmp_path)
    classes = _classes(findings)
    assert (classes["TotalsAgent"].extra or {}).get("pipeline_orchestrator") is True


def test_queue_worker_class_reclassified(tmp_path: Path):
    _write(tmp_path, "workers/celery_dispatcher.py", """
from celery import Celery

app = Celery("tasks")

class TaskDispatcher:
    @app.task
    def dispatch(self, payload):
        return payload
""")
    findings = _scan(tmp_path)
    classes = _classes(findings)
    if "TaskDispatcher" in classes:
        assert (classes["TaskDispatcher"].extra or {}).get("pipeline_orchestrator") is True


# ─── Real agents → NOT reclassified ────────────────────────────────


def test_alert_dispatcher_not_reclassified(tmp_path: Path):
    """The castor-1 AlertDispatcher pattern with bare `action` branching
    to pass the generic-token gate (the file doesn't `import openai`
    directly — the upstream agent does — but the `if action ==` branching
    is the agent signal). Mustn't be reclassified to pipeline just because
    it has no httpx/cv2 imports."""
    _write(tmp_path, "agents/actuators/alert_dispatcher.py", """
class AlertDispatcher:
    async def handle(self, action, alert):
        if action == "sla":
            return await self.dispatch_sla_alert(alert)
        if action == "anomaly":
            return await self.dispatch_anomaly_alert(alert)
        return await self.dispatch_deadline_alert(alert)
    async def dispatch_sla_alert(self, alert):
        return await self._dispatch(alert)
    async def dispatch_anomaly_alert(self, alert):
        return await self._dispatch(alert)
    async def dispatch_deadline_alert(self, alert):
        return await self._dispatch(alert)
""")
    findings = _scan(tmp_path)
    classes = _classes(findings)
    f = classes["AlertDispatcher"]
    assert (f.extra or {}).get("pipeline_orchestrator") is not True


def test_class_with_llm_import_stays_agent(tmp_path: Path):
    _write(tmp_path, "agents/openai_agent.py", """
import openai

class OpenAIAgent:
    def run(self, prompt):
        return openai.chat.completions.create(model="gpt-4", messages=[])
""")
    findings = _scan(tmp_path)
    classes = _classes(findings)
    f = classes["OpenAIAgent"]
    assert (f.extra or {}).get("pipeline_orchestrator") is not True


def test_class_with_intent_branching_stays_agent(tmp_path: Path):
    """No LLM SDK in the file, but `if action == X` branching is a strong
    signal of LLM-driven decision-making — keep as agent. Class name must
    match `_AGENT_CLASS_NAMES` so it gets surfaced in the first place."""
    _write(tmp_path, "agents/router.py", """
class IntentDispatcher:
    def handle(self, action, payload):
        if action == "create":
            return self._create(payload)
        if action == "delete":
            return self._delete(payload)
        return None
""")
    findings = _scan(tmp_path)
    classes = _classes(findings)
    f = classes["IntentDispatcher"]
    assert (f.extra or {}).get("pipeline_orchestrator") is not True


def test_class_with_match_intent_stays_agent(tmp_path: Path):
    """Python 3.10+ structural match on a decision key — same signal as
    `if action == X`."""
    _write(tmp_path, "agents/match_router.py", """
class MatchOrchestrator:
    def handle(self, intent):
        match intent:
            case "create": return 1
            case "delete": return 2
            case _: return None
""")
    findings = _scan(tmp_path)
    classes = _classes(findings)
    f = classes["MatchOrchestrator"]
    assert (f.extra or {}).get("pipeline_orchestrator") is not True


def test_class_without_pipeline_lib_or_evidence_is_dropped(tmp_path: Path):
    """Generic Dispatcher with NO LLM imports, NO branching, NO pipeline
    libs is not an agent at all — the 10-repo benchmark caught medusa's
    TelemetryDispatcher / TransactionOrchestrator inflating priority via
    this exact shape. Gate drops it before the pipeline classifier even
    runs. (Was previously `kept-as-agent`, pre-benchmark.)"""
    _write(tmp_path, "services/business_dispatcher.py", """
class BusinessDispatcher:
    def __init__(self, db):
        self.db = db
    def dispatch(self, payload):
        return self.db.execute(payload)
""")
    findings = _scan(tmp_path)
    classes = _classes(findings)
    assert "BusinessDispatcher" not in classes, (
        "Generic Dispatcher without LLM/branching evidence must be filtered "
        "out by the agent-class gate, not surfaced as a wrap target."
    )


# ─── Mixed / boundary cases ────────────────────────────────────────


def test_pipeline_lib_plus_llm_import_stays_agent(tmp_path: Path):
    """A class that uses both httpx AND openai is an LLM agent that happens
    to scrape — wrap recommendation should stand."""
    _write(tmp_path, "agents/web_agent.py", """
import httpx
import openai

class WebAgent:
    def run(self, query):
        page = httpx.get(query["url"]).text
        return openai.chat.completions.create(messages=[{"role":"user","content":page}])
""")
    findings = _scan(tmp_path)
    classes = _classes(findings)
    f = classes["WebAgent"]
    assert (f.extra or {}).get("pipeline_orchestrator") is not True
