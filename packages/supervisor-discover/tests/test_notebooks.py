"""Tests for the .ipynb notebook support in scanners._utils."""
from __future__ import annotations

import json
from pathlib import Path

from supervisor_discover.scanners import scan_all
from supervisor_discover.scanners._utils import _extract_notebook_python, safe_read


def _make_nb(cells: list[dict]) -> str:
    return json.dumps({"cells": cells, "metadata": {}, "nbformat": 4, "nbformat_minor": 5})


def test_notebook_extracts_python_from_code_cells(tmp_path: Path):
    nb_path = tmp_path / "demo.ipynb"
    nb_path.write_text(_make_nb([
        {"cell_type": "code", "source": "import os\nprint('hi')"},
        {"cell_type": "markdown", "source": "# this is a header — must be ignored"},
        {"cell_type": "code", "source": ["import openai\n", "openai.OpenAI()\n"]},
    ]))
    py = _extract_notebook_python(nb_path)
    assert "import os" in py
    assert "import openai" in py
    assert "openai.OpenAI()" in py
    # Markdown content must NOT leak into the extracted Python — would break ast.parse.
    assert "this is a header" not in py
    # safe_read should return the same thing for .ipynb.
    assert safe_read(nb_path) == py


def test_notebook_magics_are_commented_out(tmp_path: Path):
    """`%timeit` and `!ls` are IPython-only — they'd fail ast.parse, breaking
    every Python scanner. Verify they're prefixed with `# ` so AST is happy."""
    nb_path = tmp_path / "magics.ipynb"
    nb_path.write_text(_make_nb([
        {"cell_type": "code", "source": "%timeit print(1)\n!ls -la\nx = 1"},
    ]))
    py = _extract_notebook_python(nb_path)
    assert "# %timeit print(1)" in py
    assert "# !ls -la" in py
    assert "x = 1" in py
    # Round-trip: must parse without SyntaxError.
    import ast
    ast.parse(py)


def test_notebook_llm_call_fires_via_existing_scanner(tmp_path: Path):
    """End-to-end: an .ipynb that imports openai and calls .messages.create
    should produce a llm-calls finding, same as a .py file would."""
    (tmp_path / "agent.ipynb").write_text(_make_nb([
        {"cell_type": "code", "source": (
            "from anthropic import Anthropic\n"
            "client = Anthropic()\n"
            "resp = client.messages.create(model='claude-3', messages=[])\n"
        )},
    ]))
    findings = scan_all(tmp_path)
    llm = [f for f in findings if f.scanner == "llm-calls"]
    assert llm, f"expected at least one llm-calls finding, got {[f.scanner for f in findings]}"
    assert any("agent.ipynb" in f.file for f in llm)


def test_notebook_with_invalid_json_returns_none(tmp_path: Path):
    """Broken .ipynb must not crash the scan — safe_read returns None, the
    scanners just skip the file."""
    bad = tmp_path / "broken.ipynb"
    bad.write_text("{not valid json")
    assert safe_read(bad) is None
