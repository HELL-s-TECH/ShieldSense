"""Rule-based classifier: fast, explainable structural checks.

This is the first tier of the pipeline. It resolves clear-cut cases on its
own; anything it isn't confident about should be escalated to the RAG/LLM
reasoning tier (built in a later step), not force-fit into a verdict here.
"""

from dataclasses import dataclass, field

from rapidfuzz import fuzz

from detector.preprocess import Features, preprocess
from detector.reputation import check_urls
from detector.text_model import predict_phishing_probability
from detector.url_features import analyze_url

# Brands commonly impersonated in phishing — used only to catch lookalike
# domains (e.g. "paypa1-secure.com"), never as a literal blocklist.
KNOWN_BRANDS = [
    "paypal.com", "amazon.com", "linkedin.com", "google.com", "microsoft.com",
    "apple.com", "netflix.com", "facebook.com", "instagram.com", "chase.com",
    "bankofamerica.com", "wellsfargo.com", "dropbox.com", "docusign.com",
]

# Domains that get a trust boost: your own org, plus a short list of large
# platforms unlikely to be the literal sender of a scam at this domain.
ORG_DOMAIN = "yourcompany.com"
TRUSTED_DOMAINS = {"linkedin.com", "google.com", "microsoft.com", "github.com"}

EXECUTABLE_EXTENSIONS = {"exe", "scr", "bat", "cmd", "js", "vbs", "jar", "msi", "ps1"}

# Fallback only, used if the trained model (detector/text_model.py) isn't
# available for some reason — the real scoring is the TF-IDF + Logistic
# Regression model trained on 82k labeled emails (train_text_model.py).
URGENCY_KEYWORDS = [
    "verify", "suspend", "immediately", "urgent", "action required",
    "action needed", "within 24 hours", "within 12 hours", "confirm your",
    "unusual activity", "avoid penalty", "log in", "click here", "act now",
    "limited time", "overdue", "pay now", "deadline", "before friday",
    "could not be delivered", "secure your account",
]

TEXT_MODEL_PROBABILITY_THRESHOLDS = [(0.9, 3), (0.7, 2), (0.5, 1)]  # (min P(phishing), points)

LOOKALIKE_SIMILARITY_THRESHOLD = 78  # 0-100; high but not identical = typosquat


@dataclass
class Verdict:
    label: str          # "safe" | "suspicious" | "dangerous"
    score: int
    confidence: str      # "high" | "low" — low confidence should escalate to RAG/LLM
    reasons: list[str] = field(default_factory=list)


def _domain_lookalike_score(domain: str | None) -> tuple[int, str | None]:
    if not domain:
        return 0, None
    best_brand, best_ratio = None, 0
    for brand in KNOWN_BRANDS:
        brand_label = brand.split(".")[0]
        domain_label = domain.split(".")[0].split("-")[0]
        ratio = fuzz.ratio(domain_label, brand_label)
        if ratio > best_ratio:
            best_brand, best_ratio = brand, ratio
    if best_brand and domain != best_brand and best_ratio >= LOOKALIKE_SIMILARITY_THRESHOLD:
        return 3, best_brand
    return 0, None


def _keyword_fallback_score(text: str) -> tuple[int, list[str]]:
    hits = [kw for kw in URGENCY_KEYWORDS if kw in text]
    return min(len(hits), 3), hits


def _text_score(text: str) -> tuple[int, list[str]]:
    probability = predict_phishing_probability(text)
    if probability is None:
        pts, hits = _keyword_fallback_score(text)
        if not pts:
            return 0, []
        return pts, ["uses urgency/pressure language: " + ", ".join(f'"{h}"' for h in hits[:3])]

    for threshold, points in TEXT_MODEL_PROBABILITY_THRESHOLDS:
        if probability >= threshold:
            return points, [f"trained language model estimates a {probability:.0%} chance this reads like phishing"]
    return 0, []


def _url_score(urls: list[str]) -> tuple[int, list[str]]:
    total, reasons = 0, []
    for url in urls[:3]:  # a scan item realistically has at most a couple of links worth scoring
        signals = analyze_url(url)
        if signals.score:
            total += signals.score
            reasons.append(f"link {url!r} " + ", ".join(signals.reasons))
    return min(total, 6), reasons


REPUTATION_FLAG_SCORE = 6  # alone enough to cross the "dangerous" threshold


def _reputation_score(urls: list[str]) -> tuple[int, list[str]]:
    """Independent of every lexical check above: asks whether this exact
    URL is already on Google Safe Browsing's known-bad list. Catches the
    case lexical analysis structurally can't — a domain with a completely
    ordinary-looking name that's nonetheless a known malware/phishing site.
    Silently contributes nothing if no API key is configured (see
    reputation.py) — this is a bonus signal, not a requirement.
    """
    result = check_urls(urls)
    if result is None or not result.flagged:
        return 0, []
    threats = ", ".join(t.replace("_", " ").title() for t in result.threat_types)
    return REPUTATION_FLAG_SCORE, [f"URL is on Google Safe Browsing's list of known malicious sites ({threats})"]


def _attachment_score(extensions: list[str]) -> int:
    if not extensions:
        return 0
    # a double extension ending in something executable (invoice.pdf.exe)
    # is a stronger signal than a bare .exe, but both count.
    if extensions[-1] in EXECUTABLE_EXTENSIONS:
        return 5 if len(extensions) > 1 else 4
    return 0


def classify(item: dict) -> Verdict:
    features = preprocess(item)
    return classify_features(features)


def classify_features(features: Features) -> Verdict:
    reasons: list[str] = []
    score = 0

    lookalike_pts, brand = _domain_lookalike_score(features.sender_registered_domain)
    if lookalike_pts:
        score += lookalike_pts
        reasons.append(f'sender domain "{features.sender_domain}" looks like a lookalike for {brand}')

    if features.sender_registered_domain == ORG_DOMAIN:
        score -= 3
        reasons.append("sender is your own organization's domain")
    elif features.sender_registered_domain in TRUSTED_DOMAINS:
        score -= 3
        reasons.append(f"sender domain ({features.sender_registered_domain}) is a recognized platform")
    elif features.sender_domain:
        score += 2
        reasons.append(f"sender domain ({features.sender_domain}) isn't a recognized address")

    text_pts, text_reasons = _text_score(features.prose_text)
    if text_pts:
        score += text_pts
        reasons.extend(text_reasons)

    url_pts, url_reasons = _url_score(features.urls)
    if url_pts:
        score += url_pts
        reasons.extend(url_reasons)

    reputation_pts, reputation_reasons = _reputation_score(features.urls)
    if reputation_pts:
        score += reputation_pts
        reasons.extend(reputation_reasons)

    attach_pts = _attachment_score(features.attachment_extensions)
    if attach_pts:
        score += attach_pts
        reasons.append(f'attachment "{features.attachment_name}" has an executable extension')

    score = max(score, 0)

    if score >= 5:
        label, confidence = "dangerous", "high"
    elif score >= 2:
        label, confidence = "suspicious", "low"
    else:
        label, confidence = "safe", "high" if reasons else "low"

    if not reasons:
        reasons.append("no structural red flags found")

    return Verdict(label=label, score=score, confidence=confidence, reasons=reasons)
