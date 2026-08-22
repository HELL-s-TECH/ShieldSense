"""Reasoning tier: only called for low-confidence (ambiguous) classifier results.

Uses an LLM, via the retrieved similar cases as context, when a key is
configured — Claude (ANTHROPIC_API_KEY, sk-ant-...) or Grok/xAI
(XAI_API_KEY, or an xai-... key saved under either variable name).
Without a working key, falls back to a template built from the
classifier's own reasons — so the pipeline runs end to end today, and
upgrades automatically the moment a key is added. Nothing downstream
needs to change either way.
"""

import logging
import os
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("shieldsense.reasoner")
logger.setLevel(logging.INFO)
_log_path = Path(__file__).resolve().parent.parent / "data" / "reasoner_debug.log"
_log_path.parent.mkdir(parents=True, exist_ok=True)
_handler = logging.FileHandler(_log_path, encoding="utf-8")
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(_handler)
logger.propagate = False

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


def resolve_provider() -> tuple[str, str] | None:
    """Returns (provider, key) for whichever LLM is configured, checking the
    key's actual prefix rather than trusting the env var name alone — keys
    get pasted into the wrong-named variable often enough that this is worth
    being defensive about.
    """
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    xai_key = os.environ.get("XAI_API_KEY")

    if xai_key:
        return ("xai", xai_key)
    if anthropic_key and anthropic_key.startswith("xai-"):
        logger.info("ANTHROPIC_API_KEY holds an xai- key — routing to Grok instead of Claude")
        return ("xai", anthropic_key)
    if anthropic_key:
        return ("anthropic", anthropic_key)
    return None


def _build_user_prompt(features: Features, verdict: Verdict, similar: list[SimilarCase]) -> str:
    similar_block = "\n".join(f"- {s.subject!r} was judged {s.verdict}" for s in similar) or "none found"
    return (
        f"Content being scanned:\n{features.text[:1500]}\n\n"
        f"Sender domain: {features.sender_domain or 'unknown'}\n"
        f"Attachment: {features.attachment_name or 'none'}\n\n"
        f"Rule-based signals already found: {'; '.join(verdict.reasons)}\n"
        f"Rule-based score: {verdict.score} (tentative label: {verdict.label})\n\n"
        f"Similar past cases:\n{similar_block}\n\n"
        "In 1-2 sentences, explain what's actually going on here for the person who received it."
    )


def call_anthropic(api_key: str, user_prompt: str, system: str = SYSTEM_PROMPT) -> str:
    import anthropic

    client = anthropic.Anthropic(api_key=api_key)
    response = client.messages.create(
        model="claude-sonnet-5",
        max_tokens=150,
        system=system,
        messages=[{"role": "user", "content": user_prompt}],
    )
    return response.content[0].text.strip()


def call_xai(api_key: str, user_prompt: str, system: str = SYSTEM_PROMPT) -> str:
    import openai

    client = openai.OpenAI(api_key=api_key, base_url="https://api.x.ai/v1")
    response = client.chat.completions.create(
        model="grok-4",
        max_tokens=150,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user_prompt},
        ],
    )
    return response.choices[0].message.content.strip()


def _llm_explanation(features: Features, verdict: Verdict, similar: list[SimilarCase]) -> str | None:
    resolved = resolve_provider()
    if not resolved:
        logger.warning("No ANTHROPIC_API_KEY or XAI_API_KEY set in this process — falling back to template")
        return None
    provider, api_key = resolved
    logger.info("%s key found, length=%d, prefix=%s — calling %s", provider, len(api_key), api_key[:7], provider)

    user_prompt = _build_user_prompt(features, verdict, similar)

    try:
        if provider == "xai":
            text = call_xai(api_key, user_prompt)
        else:
            text = call_anthropic(api_key, user_prompt)
        logger.info("%s call succeeded (%d chars back)", provider, len(text))
        return text
    except ImportError as exc:
        logger.warning("%s package not installed (%s) — falling back to template", provider, exc)
        return None
    except Exception as exc:
        logger.warning("%s call failed (%s: %s) — falling back to template", provider, type(exc).__name__, exc)
        return None


def reason(features: Features, verdict: Verdict) -> Explanation:
    similar = retrieve(features)

    llm_text = _llm_explanation(features, verdict, similar)
    if llm_text:
        return Explanation(text=llm_text, source="llm")

    return Explanation(text=_template_explanation(verdict, similar), source="template")
