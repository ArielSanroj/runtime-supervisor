"""Detect filesystem + shell execution — the agent reaches into the host OS.

Attack shapes covered:
- Agent deletes files / directories on the host (logs, user data, source code).
- Agent writes arbitrary files (overwrite configs, plant malware, exfil data).
- Agent executes shell commands (RCE-equivalent if the agent's context is attacker-controlled).

Python patterns: os.remove, os.unlink, shutil.rmtree, subprocess.run / Popen,
os.system, os.popen, pathlib.Path.unlink.
TS/JS patterns: fs.unlinkSync, fs.rmSync, fs.writeFileSync, child_process.exec,
child_process.spawn, execSync.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..findings import Finding
from ._utils import python_files, safe_read, ts_js_files

# Destructive fs operations — almost always critical
_DESTRUCTIVE_FS = [
    (re.compile(r"\b(?:os\.(?:remove|unlink)|shutil\.rmtree)\s*\("), "fs-delete", "high"),
    (re.compile(r"\bPath\([^)]*\)\.unlink\s*\("), "fs-delete", "high"),
    (re.compile(r"\bfs\.(?:unlinkSync|rmSync|rmdirSync)\s*\(|\bfs\.promises\.(?:unlink|rm|rmdir)\s*\("),
     "fs-delete", "high"),
]

# Writes — high value but can be legit. Medium confidence — operator filters.
_FS_WRITES = [
    (re.compile(r"\bfs\.writeFileSync\s*\(|\bfs\.promises\.writeFile\s*\(|\bfsync?\.writeFile\s*\("),
     "fs-write", "medium"),
    (re.compile(r"\bwith\s+open\s*\([^)]*['\"]w['\"]"), "fs-write", "medium"),
]

# Shell execution — always critical when inside agent code
_SHELL_EXEC = [
    (re.compile(r"\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\("), "shell-exec", "high"),
    (re.compile(r"\bos\.system\s*\(|\bos\.popen\s*\("), "shell-exec", "high"),
    (re.compile(r"\bchild_process\.(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\("),
     "shell-exec", "high"),
    (re.compile(r"\bexeca\s*\(|\bexeca\.command\s*\("), "shell-exec", "high"),
]

_RATIONALES = {
    "fs-delete": (
        "Destructive filesystem op — agent can delete files / directories on the host. "
        "A prompt-injected agent could run `rm -rf` equivalent on logs, user data, or the "
        "source tree itself. Gate with @supervised('tool_use')."
    ),
    "fs-write": (
        "Filesystem write — agent can create or overwrite files. Risk: config overwrite, "
        "credential plant, payload staging. Medium confidence because most writes are "
        "legit; review per call-site."
    ),
    "shell-exec": (
        "Shell / subprocess execution — agent can run arbitrary host commands. If the "
        "command or its args flow from an LLM or from user input, this is RCE-equivalent. "
        "Gate with @supervised('tool_use') at minimum; prefer explicit tool allowlist."
    ),
}


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in list(python_files(root)) + list(ts_js_files(root)):
        text = safe_read(path)
        if text is None:
            continue
        for family, group in (
            ("fs-delete", _DESTRUCTIVE_FS),
            ("fs-write", _FS_WRITES),
            ("shell-exec", _SHELL_EXEC),
        ):
            for pattern, label, severity in group:
                for m in pattern.finditer(text):
                    line = text[: m.start()].count("\n") + 1
                    findings.append(Finding(
                        scanner="fs-shell",
                        file=str(path),
                        line=line,
                        snippet=m.group(0)[:80],
                        suggested_action_type="tool_use",
                        confidence=severity,
                        rationale=_RATIONALES[family],
                        extra={"family": family, "label": label},
                    ))
    return findings
