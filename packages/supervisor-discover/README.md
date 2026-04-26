# supervisor-discover

CLI scanner for AI-agent repos. Walks the source tree, finds the unsafe call-sites your LLM can fire (Stripe refunds, DB DELETEs, shell exec, file writes, agent orchestrator chokepoints, prompt injection vectors), and emits a `runtime-supervisor/` directory with the diagnosis + ready-to-paste guard wrappers + base policies.

This is the same scanner that powers the public scan flow at [vibefixing.me/scan](https://vibefixing.me/scan). The CLI runs locally so your code never leaves your machine.

## Install

```bash
pipx install supervisor-discover     # recommended — keeps it isolated
# or
pip install supervisor-discover
```

## Use

```bash
supervisor-discover scan --path /path/to/your/repo
```

This drops a `runtime-supervisor/` directory next to your code:

```
runtime-supervisor/
├── SUMMARY.md                    Human-readable diagnosis: stack, top risks, agent map
├── report.md                     Per-tier finding tables (money / real-world / data / LLM)
├── ROLLOUT.md                    Step-by-step plan: shadow → sample → enforce
├── findings.json                 Raw findings (machine-readable; same shape the web shows)
├── combos/                       Multi-step attack paths detected (e.g. LLM → fs-write)
│   ├── llm-shell-exec.md
│   └── ...
├── policies/                     Base YAML policies you can promote to production
│   ├── payment.base.v1.yaml
│   └── ...
└── stubs/                        Copy-paste wrapper code per finding family
    └── ...
```

## What it scans

Six tiers, ordered by blast radius:

| Tier | What | Examples |
|---|---|---|
| Money movement | Direct charges / refunds / payouts | `stripe.refunds.create`, `paypal.payouts.create` |
| Real-world actions | Side effects an LLM can fire | `twilio.messages.create`, `smtplib.SMTP.send`, `subprocess.run`, `fs.unlink` |
| Customer data | Mutations on tables that contain humans | `UPDATE users SET ...`, `DELETE FROM customers` |
| Business data | Mutations on operational tables | `UPDATE orders SET ...`, `DELETE FROM trades` |
| LLM tool-use | Agent calls + framework chokepoints | LangChain executors, MCP tool dispatchers, Anthropic/OpenAI clients |
| General | HTTP routes + cron schedules (informational) | FastAPI routers, Celery beat |

## Combos: multi-step attack paths

Beyond single findings, the scanner detects pairs that together are dangerous:

- **LLM + filesystem write** — your agent can rewrite its own prompt or your config files
- **Voice clone + outbound call** — ElevenLabs + Twilio = social-engineering by phone
- **LLM + shell-exec** — RCE through prompt injection
- **Agent orchestrator + tool registration** — the choke point: one wrap covers all tools

Each combo gets its own playbook in `runtime-supervisor/combos/` with the minimum guard and the ideal guard.

## How this fits with the rest of the product

```
supervisor-discover (this CLI)        ← diagnoses your repo, free, runs locally
        ↓
@runtime-supervisor/guards (npm)      ← drops 5 lines of wrappers into your code
supervisor-guards (PyPI)
        ↓
runtime-supervisor backend            ← evaluates each call against policies + threats
(self-host or vibefixing.me hosted)
        ↓
dashboard at vibefixing.me/dashboard  ← shadow / sample / enforce, review queue, audit chain
```

The CLI is open-source (Apache-2.0). The hosted backend + dashboard are at [vibefixing.me](https://vibefixing.me) — `Builder` ($29/mo) unlocks private repo scans, scan history, and CI integration. `Pro` ($99/workspace/mo) adds team workflows, SSO, and org controls.

## Self-host

If you'd rather not point your shadow events at our hosted supervisor, you can run the whole stack locally with Docker (see the main repo). The SDK accepts `SUPERVISOR_BASE_URL=http://localhost:8000` and the same wrapper code keeps working.

## License

Apache-2.0. Copyright 2026 Ariel San Martín.
