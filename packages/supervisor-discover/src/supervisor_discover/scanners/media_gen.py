"""Detect generative-media actions — the agent creates synthetic image / video.

Attack shapes:
- Agent generates deepfake / non-consensual imagery.
- Agent burns tokens in infinite loops on expensive endpoints ($/image adds up).
- Agent exfiltrates content by passing private data into image prompts.

Providers: fal.ai, Replicate, Runway, Stability AI, Midjourney (via API proxies),
OpenAI DALL-E / images.generate, Anthropic (no image gen as of now — skip).
"""
from __future__ import annotations

import re
from pathlib import Path

from ..findings import Finding
from ._utils import python_files, safe_read, ts_js_files

_SIGNATURES: list[tuple[re.Pattern, str, str]] = [
    # fal.ai — both Python client and TS client
    (re.compile(r"\bfal_client\.(?:run|submit|subscribe)\s*\("), "fal.ai", "high"),
    (re.compile(r"\bfal\.(?:run|subscribe|stream)\s*\("), "fal.ai", "high"),
    (re.compile(r"fal\.run/\S*"), "fal.ai", "high"),
    # Replicate
    (re.compile(r"\breplicate\.(?:run|predictions\.create)\s*\("), "replicate", "high"),
    (re.compile(r"api\.replicate\.com/v1/predictions"), "replicate", "high"),
    # Runway
    (re.compile(r"api\.runwayml\.com/\S*"), "runway", "high"),
    (re.compile(r"\brunway[\w.]*\.(?:tasks|images|videos)\b"), "runway", "high"),
    # Stability
    (re.compile(r"api\.stability\.ai/\S*"), "stability", "high"),
    (re.compile(r"\bstability[\w.]*\.(?:generation|images)\b"), "stability", "high"),
    # OpenAI image generation (DALL-E)
    (re.compile(r"\bopenai[\w.]*\.images\.(?:generate|create_variation|edit)\s*\("), "openai-images", "high"),
    (re.compile(r"api\.openai\.com/v1/images"), "openai-images", "high"),
    # Black Forest Labs / Flux via common hosts
    (re.compile(r"api\.bfl\.ml/\S*"), "flux", "high"),
    # Luma
    (re.compile(r"api\.lumalabs\.ai/\S*"), "luma", "high"),
    # ElevenLabs sound (voice handled in voice_actions; sound effects land here)
    (re.compile(r"api\.elevenlabs\.io/\S*/sound-generation"), "elevenlabs-sfx", "medium"),
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


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in list(python_files(root)) + list(ts_js_files(root)):
        text = safe_read(path)
        if text is None:
            continue
        for pattern, provider, severity in _SIGNATURES:
            for m in pattern.finditer(text):
                line = text[: m.start()].count("\n") + 1
                findings.append(Finding(
                    scanner="media-gen",
                    file=str(path),
                    line=line,
                    snippet=m.group(0)[:80],
                    suggested_action_type="tool_use",
                    confidence=severity,
                    rationale=_NARRATIVES.get(provider, _FALLBACK),
                    extra={"provider": provider},
                ))
    return findings
