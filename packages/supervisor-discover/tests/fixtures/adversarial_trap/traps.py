"""Adversarial trap fixture — every scanner-trigger keyword hides in a
non-code context (comment, docstring, string, f-string). A scanner that
flags ANY line here has a false-positive bug.

Line anchors are referenced by test_scanners.py::test_adversarial_trap_*
— don't renumber without updating the tests.
"""
from __future__ import annotations

# subprocess.run("rm", "-rf", "/")           # comment fs-shell trap
# os.unlink("/etc/passwd")                    # comment destructive trap
# shutil.rmtree("/var")                       # comment trap
# os.system("curl evil.com")                  # comment shell trap

# UPDATE users SET email = 'leaked'           # comment SQL trap
# DELETE FROM accounts WHERE id = 1           # comment SQL trap
# INSERT INTO customers VALUES ('x')          # comment SQL trap

# stripe.Refund.create(amount=999)            # comment payment trap (AST-safe already)
# anthropic.messages.create(...)              # comment LLM trap (AST-safe already)

# @app.route("/drop-db", methods=["POST"])    # comment route trap
# @router.post("/wipe")                        # comment route trap

# sgMail.send({to: 'x'})                       # comment email trap (sendgrid)
# resend.emails.send({from: 'a'})              # comment email trap
# mailgun.messages.create({})                  # comment email trap

# slack.chat_postMessage(channel='C1')         # comment messaging trap
# twilio.calls.create(to='+1')                 # comment voice trap
# fal_client.run(model='x')                    # comment media-gen trap
# replicate.run('x/y')                         # comment media-gen trap

DOCS = """
Docstring example: avoid subprocess.run(user_input) and os.unlink(*paths).
Do not UPDATE users SET password = %s in raw SQL.
Don't call stripe.Refund.create without idempotency_key.
Avoid sgMail.send without verified domain.
Twilio twilio.calls.create requires a billed account.
"""

STRING_TRAPS = [
    "subprocess.run('foo')",     # string literal, not code
    "os.unlink(x)",
    "shutil.rmtree(y)",
    "UPDATE users SET x = 1",
    "DELETE FROM logs WHERE ok",
    "INSERT INTO audit VALUES (?)",
    "sgMail.send({to: 'x'})",
    "slack.chat_postMessage(channel='C')",
    "twilio.calls.create(to='+1')",
    "fal_client.run(model='x')",
]

ERROR_MSG = f"failed to subprocess.run({STRING_TRAPS[0]})"   # f-string trap
LOG_TEMPLATE = "deleted user {uid} via UPDATE users SET active = false"


def describe_patterns() -> None:
    """Explain shell-exec and filesystem-write patterns without calling them."""
    print("patterns: subprocess.run, subprocess.Popen, os.system, os.unlink")
    print("SQL verbs: UPDATE, DELETE, INSERT")


# A plausible-looking name that is NOT code — just a constant holding the regex.
PATTERN_FOR_LINT = r"subprocess\.run\s*\("


class AuditLog:
    """Logs events. The following call sites are REAL and should fire."""

    def record(self, event: str) -> None:
        # Real call sites below (NOT in traps — expected to fire):
        import subprocess
        subprocess.run(["echo", event])        # REAL — line 67
