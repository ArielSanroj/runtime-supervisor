"""Detect generative-media actions — the agent creates synthetic image / video.

Attack shapes:
- Agent generates deepfake / non-consensual imagery.
- Agent burns tokens in infinite loops on expensive endpoints ($/image adds up).
- Agent exfiltrates content by passing private data into image prompts.

Providers: fal.ai, Replicate, Runway, Stability AI, Midjourney (via API proxies),
OpenAI DALL-E / images.generate.

Python: AST-based dotted-name matching. JS/TS + URL patterns: regex.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..findings import Finding
from ._utils import iter_python_calls, match_dotted_call, python_files, safe_read, ts_js_files


_PY_CALL_TARGETS: dict[str, tuple[str, str]] = {
    # Vendor-qualified dotted names only — prevents `images.generate` from
    # matching a custom `my_local.images.generate()` helper in an unrelated repo.
    "fal_client.run":         ("fal.ai", "high"),
    "fal_client.submit":      ("fal.ai", "high"),
    "fal_client.subscribe":   ("fal.ai", "high"),
    "fal.run":                ("fal.ai", "high"),
    "fal.subscribe":          ("fal.ai", "high"),
    "fal.stream":             ("fal.ai", "high"),
    "replicate.run":          ("replicate", "high"),
    "replicate.predictions.create": ("replicate", "high"),
    "openai.images.generate":         ("openai-images", "high"),
    "openai.images.create_variation": ("openai-images", "high"),
    "openai.images.edit":             ("openai-images", "high"),
    "client.images.generate":         ("openai-images", "high"),
    "client.images.edit":             ("openai-images", "high"),
}

_URL_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"fal\.run/\S*"), "fal.ai", "high"),
    (re.compile(r"api\.replicate\.com/v1/predictions"), "replicate", "high"),
    (re.compile(r"api\.runwayml\.com/\S*"), "runway", "high"),
    (re.compile(r"api\.stability\.ai/\S*"), "stability", "high"),
    (re.compile(r"api\.openai\.com/v1/images"), "openai-images", "high"),
    (re.compile(r"api\.bfl\.ml/\S*"), "flux", "high"),
    (re.compile(r"api\.lumalabs\.ai/\S*"), "luma", "high"),
    (re.compile(r"api\.elevenlabs\.io/\S*/sound-generation"), "elevenlabs-sfx", "medium"),
]

_JS_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"\bfal_client\.(?:run|submit|subscribe)\s*\("), "fal.ai", "high"),
    (re.compile(r"\bfal\.(?:run|subscribe|stream)\s*\("), "fal.ai", "high"),
    (re.compile(r"\breplicate\.(?:run|predictions\.create)\s*\("), "replicate", "high"),
    (re.compile(r"\brunway[\w.]*\.(?:tasks|images|videos)\b"), "runway", "high"),
    (re.compile(r"\bstability[\w.]*\.(?:generation|images)\b"), "stability", "high"),
    (re.compile(r"\bopenai[\w.]*\.images\.(?:generate|create_variation|edit)\s*\("),
     "openai-images", "high"),
]


_NARRATIVES: dict[str, str] = {
    "fal.ai": (
        "fal.ai generative pipeline. Cheap and fast — that's the attack surface: a looped "
        "prompt injection burns hundreds of dollars in minutes. Enforce quota per-caller."
    ),
    "replicate": (
        "Replicate generative pipeline. Many open-source image/video models hosted here, "
        "including ones with weak content filters. Output can be deepfake or NSFW."
    ),
    "runway": (
        "Runway video generation. Higher per-call cost — a compromised agent can drain "
        "budget fast. Output is video, so the deepfake / disinformation potential is real."
    ),
    "stability": (
        "Stability AI image generation (SDXL / SD3). Widely used, widely abused. Content "
        "filter bypass via prompt manipulation is a known attack class."
    ),
    "openai-images": (
        "OpenAI DALL-E. Content policy blocks the obvious stuff, but prompt injection can "
        "still leak data via embedded images (agent asked to 'render this customer's info "
        "as a poster'), and costs add up."
    ),
    "flux": (
        "Black Forest Labs Flux. High-quality image model with less strict content filtering "
        "than OpenAI — higher risk of generating disinformation imagery."
    ),
    "luma": (
        "Luma Labs (Dream Machine). Text-to-video. Video deepfakes at scale — the highest-"
        "impact category of generative media abuse."
    ),
    "elevenlabs-sfx": (
        "ElevenLabs sound-effect generation. Low impact directly, but can be composed with "
        "voice cloning to produce convincing fake audio scenes (background noise + spoofed voice)."
    ),
}

_FALLBACK = (
    "Generative media — agent creates synthetic image/video/audio. Risks: deepfakes, "
    "cost spikes from looped calls, prompt exfiltration via embedded data."
)


def _emit(path: Path, line: int, snippet: str, provider: str, severity: str) -> Finding:
    return Finding(
        scanner="media-gen",
        file=str(path),
        line=line,
        snippet=snippet[:80],
        suggested_action_type="tool_use",
        confidence=severity,
        rationale=_NARRATIVES.get(provider, _FALLBACK),
        extra={"provider": provider},
    )


def _scan_python(path: Path, text: str) -> list[Finding]:
    out: list[Finding] = []
    source_lines = text.splitlines()
    for call in iter_python_calls(text):
        hit = match_dotted_call(call, _PY_CALL_TARGETS)
        if hit is None:
            continue
        _, (provider, severity) = hit
        snippet = source_lines[call.lineno - 1].strip() if 0 <= call.lineno - 1 < len(source_lines) else provider
        out.append(_emit(path, call.lineno, snippet, provider, severity))
    for pattern, provider, severity in _URL_PATTERNS:
        for m in pattern.finditer(text):
            line = text[: m.start()].count("\n") + 1
            out.append(_emit(path, line, m.group(0), provider, severity))
    return out


def _scan_js(path: Path, text: str) -> list[Finding]:
    out: list[Finding] = []
    for pattern, provider, severity in _JS_PATTERNS + _URL_PATTERNS:
        for m in pattern.finditer(text):
            line = text[: m.start()].count("\n") + 1
            out.append(_emit(path, line, m.group(0), provider, severity))
    return out


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in python_files(root):
        text = safe_read(path)
        if text is None:
            continue
        findings.extend(_scan_python(path, text))
    for path in ts_js_files(root):
        text = safe_read(path)
        if text is None:
            continue
        findings.extend(_scan_js(path, text))
    return findings
