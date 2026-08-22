"""Ties the tiers together and applies the guardrail: nothing is ever
recommended for blocking without being logged, and the classifier alone
never gets to say "block" without a plain-language explanation attached.
"""

from dataclasses import dataclass

from detector.classifier import Verdict, classify
from detector.preprocess import Features, preprocess
from detector.reasoner import Explanation, reason

ACTION_BY_LABEL = {
    "safe": "log_only",
    "suspicious": "alert",
    "dangerous": "recommend_block",
}


@dataclass
class ScanResult:
    label: str                 # "safe" | "suspicious" | "dangerous"
    score: int
    confidence: str
    explanation: str
    explanation_source: str    # "rules" | "template" | "llm"
    action: str                # "log_only" | "alert" | "recommend_block"
    requires_confirmation: bool


def decide(item: dict) -> ScanResult:
    features = preprocess(item)
    verdict = classify(item)

    if verdict.confidence == "low":
        explanation = reason(features, verdict)
    else:
        explanation = Explanation(text="; ".join(verdict.reasons), source="rules")

    action = ACTION_BY_LABEL[verdict.label]

    return ScanResult(
        label=verdict.label,
        score=verdict.score,
        confidence=verdict.confidence,
        explanation=explanation.text,
        explanation_source=explanation.source,
        action=action,
        requires_confirmation=action == "recommend_block",
    )
