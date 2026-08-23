"""Ties the tiers together and applies the guardrail: nothing is ever
recommended for blocking without being logged, and the classifier alone
never gets to say "block" without a plain-language explanation attached.
"""

from dataclasses import dataclass

from detector.classifier import Verdict, classify
from detector.preprocess import Features, preprocess
from detector.reasoner import LABEL_RANK, Explanation, reason

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

    label = verdict.label
    score = verdict.score

    # The LLM reads the actual content and can recognize risk the structural
    # rule tier can't (e.g. a well-known piracy/scam site with a lexically
    # clean URL). Its own risk read only ever escalates the verdict, never
    # downgrades it — so a rules-confirmed "dangerous" can't be talked down
    # by the LLM, but a rules "safe" that the LLM clearly disagrees with
    # doesn't get displayed as safe next to text saying otherwise.
    if explanation.suggested_label and LABEL_RANK.get(explanation.suggested_label, -1) > LABEL_RANK.get(label, -1):
        label = explanation.suggested_label
        score = max(score, {"suspicious": 2, "dangerous": 5}.get(label, score))

    action = ACTION_BY_LABEL[label]

    return ScanResult(
        label=label,
        score=score,
        confidence=verdict.confidence,
        explanation=explanation.text,
        explanation_source=explanation.source,
        action=action,
        requires_confirmation=action == "recommend_block",
    )
