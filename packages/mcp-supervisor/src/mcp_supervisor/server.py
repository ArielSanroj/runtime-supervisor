"""MCP server exposing runtime-supervisor tools to LLM agents.

Environment:
  SUPERVISOR_URL         (required) base URL, e.g. http://localhost:8000
  SUPERVISOR_APP_ID      (required) integration id
  SUPERVISOR_SECRET      (required) shared secret
  SUPERVISOR_SCOPES      comma-separated (default: *)

Usage in Claude Desktop config:
  {
    "mcpServers": {
      "runtime-supervisor": {
        "command": "uv",
        "args": ["run", "mcp-supervisor"],
        "env": {
          "SUPERVISOR_URL": "http://localhost:8000",
          "SUPERVISOR_APP_ID": "...",
          "SUPERVISOR_SECRET": "..."
        }
      }
    }
  }
"""
from __future__ import annotations

import os
from typing import Any

from mcp.server.fastmcp import FastMCP
from supervisor_client import Client, SupervisorError


def _client() -> Client:
    missing = [k for k in ("SUPERVISOR_URL", "SUPERVISOR_APP_ID", "SUPERVISOR_SECRET") if not os.environ.get(k)]
    if missing:
        raise RuntimeError(f"missing env: {', '.join(missing)}")
    scopes = os.environ.get("SUPERVISOR_SCOPES", "*").split(",")
    return Client(
        base_url=os.environ["SUPERVISOR_URL"],
        app_id=os.environ["SUPERVISOR_APP_ID"],
        shared_secret=os.environ["SUPERVISOR_SECRET"],
        scopes=[s.strip() for s in scopes if s.strip()],
    )


mcp = FastMCP("runtime-supervisor")


@mcp.tool()
def evaluate_action(
    action_type: str,
    payload: dict[str, Any],
    dry_run: bool = False,
) -> dict[str, Any]:
    """Evaluate a proposed agent action against runtime-supervisor.

    Returns the supervisor's decision: allow, deny, or review, with the
    reasons and risk score. If `dry_run=true`, nothing is persisted server-side.

    Use this before executing any sensitive action (refund, payment, data access, etc.)
    so the LLM agent respects policy + risk controls.
    """
    try:
        with _client() as c:
            d = c.evaluate(action_type, payload, dry_run=dry_run)
            return {
                "action_id": d.action_id,
                "decision": d.decision,
                "reasons": d.reasons,
                "risk_score": d.risk_score,
                "policy_version": d.policy_version,
            }
    except SupervisorError as e:
        return {"error": e.detail, "status_code": e.status_code}


@mcp.tool()
def list_action_types() -> list[dict[str, Any]]:
    """List the action types the supervisor can gate.

    Each entry has `id`, `title`, `status` (live or planned), `intercepted_signals`,
    and a `sample_payload`. Use this to discover what you can safely supervise.
    """
    with _client() as c:
        return c.list_action_types()


@mcp.tool()
def get_evidence(action_id: str) -> dict[str, Any]:
    """Return the tamper-evident evidence bundle for an already-evaluated action."""
    with _client() as c:
        return c.get_evidence(action_id)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
