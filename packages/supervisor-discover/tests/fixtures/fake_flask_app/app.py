"""Minimal Flask app fixture: one refund route + one LLM call + a raw SQL."""
from __future__ import annotations

import stripe
from flask import Flask, request

app = Flask(__name__)


@app.route("/refund", methods=["POST"])
def refund():
    data = request.get_json()
    return stripe.Refund.create(amount=data["amount"], charge=data["charge_id"])


@app.route("/summarize", methods=["POST"])
def summarize():
    from openai import OpenAI

    client = OpenAI()
    resp = client.chat.completions.create(model="gpt-4", messages=[{"role": "user", "content": "hi"}])
    return resp


def raw_sql_example():
    session = object()
    session.execute("UPDATE users SET email = 'x' WHERE id = 1")
    session.commit()
