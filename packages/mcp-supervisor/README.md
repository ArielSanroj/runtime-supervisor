# mcp-supervisor

MCP server that exposes runtime-supervisor as tools for LLM agents (Claude Desktop, Claude Code, any MCP-aware client).

## Install

```bash
uv pip install -e packages/mcp-supervisor
# or from PyPI once published:
pip install mcp-supervisor
```

## Configure

Environment variables:

| Variable              | Required | Description                                            |
| --------------------- | -------- | ------------------------------------------------------ |
| `SUPERVISOR_URL`      | yes      | Supervisor API base URL (e.g. `http://localhost:8000`) |
| `SUPERVISOR_APP_ID`   | yes      | Integration id issued by `POST /v1/integrations`       |
| `SUPERVISOR_SECRET`   | yes      | Shared secret returned at registration                 |
| `SUPERVISOR_SCOPES`   | no       | Comma-separated scopes (default `*`)                   |

## Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "runtime-supervisor": {
      "command": "uv",
      "args": ["--directory", "/path/to/agentic-internal-controls", "run", "mcp-supervisor"],
      "env": {
        "SUPERVISOR_URL": "http://localhost:8000",
        "SUPERVISOR_APP_ID": "your-integration-id",
        "SUPERVISOR_SECRET": "your-shared-secret",
        "SUPERVISOR_SCOPES": "refund,payment"
      }
    }
  }
}
```

## Exposed tools

- `evaluate_action(action_type, payload, dry_run=false)` — gate an agent action through policy + risk.
- `list_action_types()` — discover what's supervised (live vs planned).
- `get_evidence(action_id)` — fetch the hash-chained evidence bundle for audit.

## Example prompt to Claude

> "Before I execute a $1200 refund for a customer who signed up 18 days ago and has had 2 refunds in the last 24h, use `evaluate_action` with dry_run=true to show me what the supervisor would decide."
