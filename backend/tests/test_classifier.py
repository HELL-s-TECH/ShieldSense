"""Runs the rule-based classifier against the seed mock inbox and reports pass/fail."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detector.classifier import classify

DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "mock_inbox.json"


def main() -> int:
    items = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    failures = 0

    for item in items:
        verdict = classify(item)
        expected = item["expected_verdict"]
        ok = verdict.label == expected
        status = "PASS" if ok else "FAIL"
        if not ok:
            failures += 1

        print(f"[{status}] #{item['id']} {item['subject'][:45]!r}")
        print(f"       expected={expected}  got={verdict.label}  score={verdict.score}  confidence={verdict.confidence}")
        for reason in verdict.reasons:
            print(f"       - {reason}")
        print()

    total = len(items)
    print(f"{total - failures}/{total} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
