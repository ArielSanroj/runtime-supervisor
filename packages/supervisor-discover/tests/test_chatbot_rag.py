"""Tests for chatbot-rag repo_type detection and voice fix.

Background: cliocsbot (Express + anthropic.messages.create, no agent loop)
got scanned but the SUMMARY led with email-sends — the agent-shaped severity
ladder (`payment > email > llm`) is wrong for chat surfaces where the LLM
output IS the user-facing product. The Andrea/Prodesa hallucination incident
is what surfaced this. These tests pin the detection signals + the voice
override so the regression can't slip back in.
"""
from __future__ import annotations

from pathlib import Path

from supervisor_discover.policy_loader import load_scan_output_policy
from supervisor_discover.scanners import scan_all
from supervisor_discover.start_here import build_start_here
from supervisor_discover.summary import build_summary


def _write(tmp: Path, name: str, body: str) -> Path:
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


# ── detection ────────────────────────────────────────────────────────


def test_express_anthropic_with_route_classifies_as_chatbot_rag(tmp_path: Path):
    """The cliocsbot shape: Express server + anthropic SDK call + an HTTP
    route, no langchain, no MCP, no agent class. This is the case we missed
    in v1 of the scanner."""
    _write(
        tmp_path,
        "src/server.js",
        "import express from 'express';\n"
        "import Anthropic from '@anthropic-ai/sdk';\n"
        "const app = express();\n"
        "const client = new Anthropic();\n"
        "app.post('/chat', async (req, res) => {\n"
        "  const r = await client.messages.create({\n"
        "    model: 'claude-3', messages: req.body.messages\n"
        "  });\n"
        "  res.json(r);\n"
        "});\n",
    )
    summary = build_summary(scan_all(tmp_path), root=tmp_path)
    assert summary.repo_type == "chatbot-rag"
    assert "chatbot" in summary.one_liner.lower()


def test_python_fastapi_openai_classifies_as_chatbot_rag(tmp_path: Path):
    """Same shape, Python flavor — FastAPI + openai. Scanner picks it up the
    same way. Pinning this so the heuristic isn't accidentally JS-only."""
    _write(
        tmp_path,
        "main.py",
        "from fastapi import FastAPI\n"
        "import openai\n"
        "app = FastAPI()\n"
        "client = openai.OpenAI()\n"
        "@app.post('/chat')\n"
        "async def chat(req: dict):\n"
        "    r = client.chat.completions.create(\n"
        "        model='gpt-4', messages=req['messages']\n"
        "    )\n"
        "    return r\n",
    )
    summary = build_summary(scan_all(tmp_path), root=tmp_path)
    assert summary.repo_type == "chatbot-rag"


def test_cli_script_with_openai_is_not_chatbot(tmp_path: Path):
    """No HTTP route → not a chatbot. A one-shot script that calls the LLM
    is its own thing; the chatbot framing would mislead the reader."""
    _write(
        tmp_path,
        "summarize.py",
        "import openai\n"
        "client = openai.OpenAI()\n"
        "r = client.chat.completions.create(model='gpt-4', messages=[])\n"
        "print(r)\n",
    )
    summary = build_summary(scan_all(tmp_path), root=tmp_path)
    assert summary.repo_type != "chatbot-rag"


def test_langchain_agent_wins_over_chatbot_rag(tmp_path: Path):
    """If the repo has an explicit langchain agent surface, that's the more
    specific classification. chatbot-rag is the catch-all for direct-SDK
    chatbots; langchain has its own framing."""
    _write(
        tmp_path,
        "agent.py",
        "from fastapi import FastAPI\n"
        "from langchain.agents import AgentExecutor, create_openai_tools_agent\n"
        "app = FastAPI()\n"
        "@app.post('/chat')\n"
        "async def chat(req: dict):\n"
        "    return {}\n",
    )
    summary = build_summary(scan_all(tmp_path), root=tmp_path)
    assert summary.repo_type == "langchain-agent"


def test_no_llm_no_chatbot_classification(tmp_path: Path):
    """Express server with email + db but no LLM → not a chatbot. Pinning
    the boundary so regular Express CRUD apps don't get the chatbot voice."""
    _write(
        tmp_path,
        "src/server.js",
        "import express from 'express';\n"
        "const app = express();\n"
        "app.post('/users', (req, res) => res.json({}));\n",
    )
    summary = build_summary(scan_all(tmp_path), root=tmp_path)
    assert summary.repo_type != "chatbot-rag"


# ── priority ladder + risk-card override ─────────────────────────────


def test_chatbot_repo_leads_with_llm_calls_not_email(tmp_path: Path):
    """The bug: cliocsbot had email-sends (severity 70) and llm-calls
    (severity 30) so SUMMARY led with email. For chatbot-rag the override
    boosts llm-calls to 95, which has to win against email."""
    _write(
        tmp_path,
        "src/server.js",
        "import express from 'express';\n"
        "import Anthropic from '@anthropic-ai/sdk';\n"
        "import { sendEmail } from './mailer.js';\n"
        "const app = express();\n"
        "const client = new Anthropic();\n"
        "app.post('/chat', async (req, res) => {\n"
        "  const r = await client.messages.create({\n"
        "    model: 'claude-3', messages: req.body.messages\n"
        "  });\n"
        "  await sendEmail(req.body.user_email, 'log', r.content);\n"
        "  res.json(r);\n"
        "});\n",
    )
    _write(
        tmp_path,
        "src/mailer.js",
        "import nodemailer from 'nodemailer';\n"
        "export async function sendEmail(to, subj, body) {\n"
        "  const t = nodemailer.createTransport({});\n"
        "  await t.sendMail({ to, subject: subj, text: body });\n"
        "}\n",
    )
    findings = scan_all(tmp_path)
    summary = build_summary(findings, root=tmp_path)
    assert summary.repo_type == "chatbot-rag"

    sh = build_start_here(summary, findings, load_scan_output_policy())
    assert sh.top_risks, "expected at least one top risk"
    # llm-calls must come before email-sends for chatbots.
    families = [r.family for r in sh.top_risks]
    if "email-sends" in families and "llm-calls" in families:
        assert families.index("llm-calls") < families.index("email-sends")


def test_chatbot_risk_card_uses_conversational_framing(tmp_path: Path):
    """The override has to win — the public framing for an LLM call inside
    a chatbot must be 'LLM is talking to your users', not the agent-loop /
    prompt-injection wording. This is the regression that lets cliocsbot's
    framing slip back into agent-shaped vocabulary."""
    _write(
        tmp_path,
        "src/server.js",
        "import express from 'express';\n"
        "import Anthropic from '@anthropic-ai/sdk';\n"
        "const app = express();\n"
        "const client = new Anthropic();\n"
        "app.post('/chat', async (req, res) => {\n"
        "  const r = await client.messages.create({\n"
        "    model: 'claude-3', messages: req.body.messages\n"
        "  });\n"
        "  res.json(r);\n"
        "});\n",
    )
    findings = scan_all(tmp_path)
    summary = build_summary(findings, root=tmp_path)
    sh = build_start_here(summary, findings, load_scan_output_policy())

    llm_card = next((r for r in sh.top_risks if r.family == "llm-calls"), None)
    assert llm_card is not None
    assert llm_card.title == "LLM is talking to your users"
    assert "user-facing" in llm_card.possible_chain.lower()
    # The "do" should point at the scope helper specifically — that's the
    # whole point of the override; generic "wrap with @supervised" leaves
    # the assertion-risk problem unsolved.
    assert "assert_entities_in_scope" in llm_card.do_this_now


def test_non_chatbot_repo_keeps_default_framing(tmp_path: Path):
    """If repo_type isn't chatbot-rag, the override must not apply — the
    default copy is right for agent loops, just not for chatbots."""
    _write(
        tmp_path,
        "agent.py",
        "from langchain.agents import AgentExecutor, create_openai_tools_agent\n"
        "import openai\n"
        "client = openai.OpenAI()\n"
        "client.chat.completions.create(model='gpt-4', messages=[])\n",
    )
    findings = scan_all(tmp_path)
    summary = build_summary(findings, root=tmp_path)
    sh = build_start_here(summary, findings, load_scan_output_policy())
    llm_card = next((r for r in sh.top_risks if r.family == "llm-calls"), None)
    if llm_card is not None:
        assert llm_card.title == "LLM calls present"
