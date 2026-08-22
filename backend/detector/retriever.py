"""Retrieval tier: finds similar past cases from the known-case corpus.

This stands in for the vector-store step in the full design. It's plain
text similarity for now (no embedding model / API needed to run), which
keeps the whole pipeline runnable offline. Swapping this for real
embeddings later doesn't change anything downstream — `retrieve()` still
returns the same shape.
"""

import json
from dataclasses import dataclass
from pathlib import Path

from rapidfuzz import fuzz

from detector.preprocess import Features

CORPUS_PATH = Path(__file__).resolve().parent.parent / "data" / "mock_inbox.json"


@dataclass
class SimilarCase:
    subject: str
    verdict: str
    similarity: int


_corpus: list[dict] | None = None


def _load_corpus() -> list[dict]:
    global _corpus
    if _corpus is None:
        _corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    return _corpus


def retrieve(features: Features, top_k: int = 2) -> list[SimilarCase]:
    corpus = _load_corpus()
    scored = []
    for case in corpus:
        case_text = " ".join([case.get("subject", ""), case.get("body", "")]).lower()
        similarity = fuzz.token_set_ratio(features.text, case_text)
        if similarity >= 98:
            continue  # this *is* the item being scanned (or a near-duplicate) — not a useful comparison
        scored.append((similarity, case))

    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [
        SimilarCase(subject=case["subject"], verdict=case["expected_verdict"], similarity=sim)
        for sim, case in scored[:top_k]
        if sim > 0
    ]
