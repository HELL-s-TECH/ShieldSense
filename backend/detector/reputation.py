"""Reputation-based check: has this exact URL already been flagged as
malicious by someone else?

Everything else in the pipeline (classifier.py, url_features.py) is
lexical — it looks at the *shape* of a URL (hyphens, IP addresses, digit
density) or the wording of an email. That structurally cannot catch a
domain that looks perfectly ordinary but is already a known bad actor
(e.g. a piracy/malware site with a clean, unremarkable name) — no amount
of threshold-tuning fixes that, because the signal was never being
collected. This module adds that missing signal via Google Safe
Browsing's continuously-updated list of known malware/phishing/unwanted-
software URLs (the same list Chrome itself checks against).

Optional: with no GOOGLE_SAFE_BROWSING_API_KEY configured, or if the call
fails, this returns None and the caller treats that as "no reputation
signal available" — not "safe". The rest of the pipeline runs exactly as
before either way.
"""

import logging
import os
from dataclasses import dataclass, field

import requests

logger = logging.getLogger("shieldsense.reputation")

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]


@dataclass
class ReputationResult:
    flagged: bool
    threat_types: list[str] = field(default_factory=list)


def check_urls(urls: list[str]) -> ReputationResult | None:
    """Checks up to 3 URLs against Google Safe Browsing in a single request.

    Returns None (not "safe") when there's no key configured, no URLs to
    check, or the API call itself fails — a caller should never treat "we
    couldn't check" the same as "we checked and it's clean".
    """
    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")
    if not api_key:
        return None
    if not urls:
        return None

    payload = {
        "client": {"clientId": "shieldsense", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url} for url in urls[:3]],
        },
    }

    try:
        response = requests.post(SAFE_BROWSING_URL, params={"key": api_key}, json=payload, timeout=5)
        response.raise_for_status()
        data = response.json()
    except Exception as exc:
        logger.warning("Safe Browsing call failed (%s: %s) — skipping reputation signal", type(exc).__name__, exc)
        return None

    matches = data.get("matches", [])
    if not matches:
        logger.info("Safe Browsing checked %d url(s), no matches", len(urls[:3]))
        return ReputationResult(flagged=False)

    threat_types = sorted({match.get("threatType", "UNKNOWN") for match in matches})
    logger.info("Safe Browsing flagged a URL — threat types: %s", threat_types)
    return ReputationResult(flagged=True, threat_types=threat_types)
