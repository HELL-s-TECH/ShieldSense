"""Reasoning tier: only called for low-confidence (ambiguous) classifier results.

Uses Claude, via the retrieved similar cases as context, when
ANTHROPIC_API_KEY is set. Without a key, falls back to a template built
from the classifier's own reasons — so the pipeline runs end to end
today, and upgrades automatically the moment a key is added. Nothing
downstream needs to change either way.
"""

import os
from dataclasses import dataclass

from detector.classifier import Verdict
from detector.preprocess import Features
from detector.retriever import SimilarCase, retrieve

SYSTEM_PROMPT = """You are ShieldSense, a security agent that explains why an email, \
link, or file looks risky (or doesn't) in one or two plain-language sentences. \
Be specific about what you noticed. Do not use the words "danger" or generic \
warnings — name the actual signal. Keep it under 40 words."""


@dataclass
class Explanation:
    text: str
    source: str  # "llm" | "template"


def _template_explanation(verdict: Verdict, similar: list[SimilarCase]) -> str:
    reason_text = "; ".join(verdict.reasons)
    if similar:
        best = similar[0]
        return (
            f"{reason_text}. It's also similar to a past {best.verdict} case "
            f'("{best.subject}"), which is why this needs a closer look rather than an automatic pass.'
        )
    return f"{reason_text}. Not enough of a clear match to known good or bad patterns to resolve automatically."


def _llm_explanation(features: Features, verdict: Verdict, similar: list[SimilarCase]) -> str | None:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    try:
        import anthropic
    except ImportError:
        return None

    similar_block = "\n".join(f"- {s.subject!r} was judged {s.verdict}" for s in similar) or "none found"
    user_prompt = (
        f"Content being scanned:\n{features.text[:1500]}\n\n"
        f"Sender domain: {features.sender_domain or 'unknown'}\n"
        f"Attachment: {features.attachment_name or 'none'}\n\n"
        f"Rule-based signals already found: {'; '.join(verdict.reasons)}\n"
        f"Rule-based score: {verdict.score} (tentative label: {verdict.label})\n\n"
        f"Similar past cases:\n{similar_block}\n\n"
        "In 1-2 sentences, explain what's actually going on here for the person who received it."
    )

    try:
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model="claude-sonnet-5",
            max_tokens=150,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return response.content[0].text.strip()
    except Exception:
        return None


def reason(features: Features, verdict: Verdict) -> Explanation:
    similar = retrieve(features)

    llm_text = _llm_explanation(features, verdict, similar)
    if llm_text:
        return Explanation(text=llm_text, source="llm")

    return Explanation(text=_template_explanation(verdict, similar), source="template")
