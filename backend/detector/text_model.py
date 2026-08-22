"""Serves the trained email-text phishing classifier (see train_text_model.py).

TF-IDF + Logistic Regression, trained on 82k labeled emails (Kaggle:
naserabdullahalam/phishing-email-dataset). ~99% precision/recall on a
held-out test split. This replaces the old hardcoded urgency-keyword
list — the model has actually learned what phishing language looks like
instead of matching a fixed phrase list.
"""

from functools import lru_cache
from pathlib import Path

import joblib

MODEL_DIR = Path(__file__).resolve().parent.parent / "data" / "models"


@lru_cache(maxsize=1)
def _load():
    model = joblib.load(MODEL_DIR / "text_classifier.joblib")
    vectorizer = joblib.load(MODEL_DIR / "tfidf_vectorizer.joblib")
    return model, vectorizer


def is_available() -> bool:
    return (MODEL_DIR / "text_classifier.joblib").exists()


def predict_phishing_probability(text: str) -> float | None:
    """Returns P(phishing) in [0, 1], or None if the model isn't trained yet."""
    if not text or not text.strip():
        return None
    if not is_available():
        return None
    model, vectorizer = _load()
    vec = vectorizer.transform([text])
    return float(model.predict_proba(vec)[0][1])
