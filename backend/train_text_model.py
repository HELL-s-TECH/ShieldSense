"""Trains the email-text phishing classifier.

Dataset: naserabdullahalam/phishing-email-dataset (Kaggle) — 82,486 emails
combining Enron, Nazario, CEAS_08, SpamAssassin, Ling, and Nigerian Fraud
corpora, pre-labeled 0=legitimate / 1=phishing.

Run once to produce the saved model; detector/text_model.py loads the
result at request time. Re-run any time the dataset or feature choices
change.
"""

import time
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

DATASET_PATH = Path.home() / ".cache/kagglehub/datasets/naserabdullahalam/phishing-email-dataset/versions/1/phishing_email.csv"
MODEL_DIR = Path(__file__).resolve().parent / "data" / "models"


def main() -> None:
    print(f"Loading {DATASET_PATH} ...")
    df = pd.read_csv(DATASET_PATH)
    df = df.dropna(subset=["text_combined", "label"])
    print(f"{len(df)} rows, label balance:\n{df['label'].value_counts(normalize=True)}")

    x_train, x_test, y_train, y_test = train_test_split(
        df["text_combined"], df["label"], test_size=0.15, random_state=42, stratify=df["label"]
    )

    vectorizer = TfidfVectorizer(
        max_features=25_000,
        ngram_range=(1, 2),
        stop_words="english",
        min_df=3,
    )

    t0 = time.time()
    x_train_vec = vectorizer.fit_transform(x_train)
    x_test_vec = vectorizer.transform(x_test)
    print(f"Vectorized in {time.time() - t0:.1f}s — vocab size {len(vectorizer.vocabulary_)}")

    model = LogisticRegression(max_iter=1000, C=1.0)
    t0 = time.time()
    model.fit(x_train_vec, y_train)
    print(f"Trained in {time.time() - t0:.1f}s")

    y_pred = model.predict(x_test_vec)
    print("\n" + classification_report(y_test, y_pred, target_names=["legitimate", "phishing"]))
    print("Confusion matrix (rows=actual, cols=predicted):")
    print(confusion_matrix(y_test, y_pred))

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_DIR / "text_classifier.joblib")
    joblib.dump(vectorizer, MODEL_DIR / "tfidf_vectorizer.joblib")
    print(f"\nSaved model + vectorizer to {MODEL_DIR}")


if __name__ == "__main__":
    main()
