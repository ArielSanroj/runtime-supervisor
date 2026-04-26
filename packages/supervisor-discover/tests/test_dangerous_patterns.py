"""Tests for the new risk patterns:

  fs-shell:    eval / exec / pickle.loads / dill.load / marshal.loads
  auth-bypass: requests / httpx with verify=False, jwt.decode bypass
  db-mutations: redis flushall / flushdb

These are RCE-class / auth-bypass / data-loss primitives the scanner missed
before. The cases here are the canonical attack shapes and the canonical
benign shapes (constant-string `eval`, hardcoded list args), so a future
detector tweak that pulls one back into noise has a fixture to land on.
"""
from __future__ import annotations

from pathlib import Path

from supervisor_discover.findings import Finding
from supervisor_discover.scanners import auth_bypass, db_mutations, fs_shell


def _write(tmp: Path, name: str, body: str) -> Path:
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


def _findings_with_family(findings: list[Finding], family: str) -> list[Finding]:
    return [f for f in findings if (f.extra or {}).get("family") == family]


# ─── eval / exec ─────────────────────────────────────────────────────


def test_eval_with_variable_arg_flagged_high(tmp_path: Path):
    _write(tmp_path, "agent.py", """
def run(user_query):
    return eval(user_query)
""")
    findings = fs_shell.scan(tmp_path)
    code_eval = _findings_with_family(findings, "code-eval")
    assert len(code_eval) == 1
    assert code_eval[0].confidence == "high"


def test_eval_with_constant_string_downgraded_to_low(tmp_path: Path):
    _write(tmp_path, "lib.py", "VALUE = eval(\"2 + 2\")\n")
    findings = fs_shell.scan(tmp_path)
    code_eval = _findings_with_family(findings, "code-eval")
    assert len(code_eval) == 1
    assert code_eval[0].confidence == "low"
    assert code_eval[0].extra.get("severity_refined") is True


def test_exec_flagged(tmp_path: Path):
    _write(tmp_path, "agent.py", "def run(code): exec(code)\n")
    findings = fs_shell.scan(tmp_path)
    code_eval = _findings_with_family(findings, "code-eval")
    assert any(f.extra.get("label") == "exec" for f in code_eval)


def test_eval_in_comment_or_string_not_flagged(tmp_path: Path):
    _write(tmp_path, "lib.py", """
# We avoid eval(user_input) here on purpose.
DOC = "see eval(\\"x\\") in legacy code"
def real_call():
    return 42
""")
    findings = fs_shell.scan(tmp_path)
    code_eval = _findings_with_family(findings, "code-eval")
    assert code_eval == []


def test_js_eval_flagged(tmp_path: Path):
    _write(tmp_path, "agent.ts", "function run(x) { return eval(x); }\n")
    findings = fs_shell.scan(tmp_path)
    code_eval = _findings_with_family(findings, "code-eval")
    assert len(code_eval) >= 1


def test_js_new_function_flagged(tmp_path: Path):
    _write(tmp_path, "agent.ts", "const fn = new Function(userExpr);\n")
    findings = fs_shell.scan(tmp_path)
    code_eval = _findings_with_family(findings, "code-eval")
    assert len(code_eval) >= 1


def test_js_evaluation_word_not_flagged(tmp_path: Path):
    """Word boundaries: `evaluation` and `eval_metric` must NOT match."""
    _write(tmp_path, "metrics.ts", """
const evaluation = computeScore();
const eval_metric = 0.95;
""")
    findings = fs_shell.scan(tmp_path)
    code_eval = _findings_with_family(findings, "code-eval")
    assert code_eval == []


# ─── pickle / dill / marshal ─────────────────────────────────────────


def test_pickle_loads_flagged_high(tmp_path: Path):
    _write(tmp_path, "ingest.py", """
import pickle
def parse(data):
    return pickle.loads(data)
""")
    findings = fs_shell.scan(tmp_path)
    deser = _findings_with_family(findings, "unsafe-deserialize")
    assert len(deser) == 1
    assert deser[0].confidence == "high"


def test_pickle_load_from_file_flagged(tmp_path: Path):
    _write(tmp_path, "load.py", """
import pickle
with open('cache.pkl', 'rb') as f:
    obj = pickle.load(f)
""")
    findings = fs_shell.scan(tmp_path)
    deser = _findings_with_family(findings, "unsafe-deserialize")
    assert len(deser) == 1


def test_dill_loads_flagged(tmp_path: Path):
    _write(tmp_path, "x.py", "import dill\nobj = dill.loads(blob)\n")
    findings = fs_shell.scan(tmp_path)
    deser = _findings_with_family(findings, "unsafe-deserialize")
    assert len(deser) == 1


def test_marshal_loads_flagged(tmp_path: Path):
    _write(tmp_path, "x.py", "import marshal\nx = marshal.loads(b)\n")
    findings = fs_shell.scan(tmp_path)
    deser = _findings_with_family(findings, "unsafe-deserialize")
    assert len(deser) == 1


# ─── TLS bypass ──────────────────────────────────────────────────────


def test_requests_get_verify_false_flagged(tmp_path: Path):
    _write(tmp_path, "http.py", """
import requests
r = requests.get("https://api.example.com/v1/x", verify=False)
""")
    findings = auth_bypass.scan(tmp_path)
    tls = _findings_with_family(findings, "tls-bypass")
    assert len(tls) == 1
    assert tls[0].confidence == "medium"


def test_requests_post_verify_false_flagged(tmp_path: Path):
    _write(tmp_path, "http.py", """
import requests
requests.post("https://x", json={}, verify=False)
""")
    findings = auth_bypass.scan(tmp_path)
    tls = _findings_with_family(findings, "tls-bypass")
    assert len(tls) == 1


def test_requests_get_verify_true_not_flagged(tmp_path: Path):
    _write(tmp_path, "http.py", """
import requests
requests.get("https://x", verify=True)
requests.get("https://x")  # default verify=True
""")
    findings = auth_bypass.scan(tmp_path)
    tls = _findings_with_family(findings, "tls-bypass")
    assert tls == []


def test_bound_session_verify_false_flagged(tmp_path: Path):
    """`session = requests.Session()` then `session.get(..., verify=False)`."""
    _write(tmp_path, "http.py", """
import requests
session = requests.Session()
session.get("https://x", verify=False)
""")
    findings = auth_bypass.scan(tmp_path)
    tls = _findings_with_family(findings, "tls-bypass")
    assert len(tls) == 1


def test_js_axios_verify_false_flagged(tmp_path: Path):
    _write(tmp_path, "client.ts", """
const agent = new https.Agent({ rejectUnauthorized: false });
""")
    findings = auth_bypass.scan(tmp_path)
    tls = _findings_with_family(findings, "tls-bypass")
    assert len(tls) == 1


# ─── JWT bypass ──────────────────────────────────────────────────────


def test_jwt_decode_with_verify_false_flagged(tmp_path: Path):
    """PyJWT <2.0 syntax."""
    _write(tmp_path, "auth.py", """
import jwt
def decode(token, key):
    return jwt.decode(token, key, verify=False)
""")
    findings = auth_bypass.scan(tmp_path)
    bypass = _findings_with_family(findings, "jwt-bypass")
    assert len(bypass) == 1
    assert bypass[0].confidence == "high"


def test_jwt_decode_with_options_verify_signature_false_flagged(tmp_path: Path):
    """PyJWT 2.x syntax."""
    _write(tmp_path, "auth.py", """
import jwt
def decode(token, key):
    return jwt.decode(token, key, options={"verify_signature": False})
""")
    findings = auth_bypass.scan(tmp_path)
    bypass = _findings_with_family(findings, "jwt-bypass")
    assert len(bypass) == 1


def test_jwt_decode_with_algorithms_none_flagged(tmp_path: Path):
    _write(tmp_path, "auth.py", """
import jwt
def decode(token, key):
    return jwt.decode(token, key, algorithms=["none"])
""")
    findings = auth_bypass.scan(tmp_path)
    bypass = _findings_with_family(findings, "jwt-bypass")
    assert len(bypass) == 1


def test_jwt_decode_with_real_algorithm_not_flagged(tmp_path: Path):
    _write(tmp_path, "auth.py", """
import jwt
def decode(token, key):
    return jwt.decode(token, key, algorithms=["HS256"])
""")
    findings = auth_bypass.scan(tmp_path)
    bypass = _findings_with_family(findings, "jwt-bypass")
    assert bypass == []


# ─── Redis flush ─────────────────────────────────────────────────────


def test_redis_flushall_flagged(tmp_path: Path):
    _write(tmp_path, "cache.py", """
import redis
r = redis.Redis()
def reset():
    r.flushall()
""")
    findings = db_mutations.scan(tmp_path)
    flush = [f for f in findings if (f.extra or {}).get("family") == "redis-flush"]
    assert len(flush) == 1
    assert flush[0].extra.get("method") == "flushall"


def test_redis_flushdb_flagged(tmp_path: Path):
    _write(tmp_path, "cache.py", """
def reset(client):
    client.flushdb()
""")
    findings = db_mutations.scan(tmp_path)
    flush = [f for f in findings if (f.extra or {}).get("family") == "redis-flush"]
    assert len(flush) == 1


def test_flush_word_in_comment_not_flagged(tmp_path: Path):
    _write(tmp_path, "doc.py", """
# Don't call flushall() in production.
DOC = "flushdb is dangerous"
""")
    findings = db_mutations.scan(tmp_path)
    flush = [f for f in findings if (f.extra or {}).get("family") == "redis-flush"]
    assert flush == []


def test_js_redis_flushall_flagged(tmp_path: Path):
    _write(tmp_path, "cache.ts", """
import { Redis } from "ioredis";
const redis = new Redis();
await redis.flushall();
""")
    findings = db_mutations.scan(tmp_path)
    flush = [f for f in findings if (f.extra or {}).get("family") == "redis-flush"]
    assert len(flush) == 1
