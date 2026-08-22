"""Lexical URL features — the same family of signals the phishing-URL
literature (and the classic UCI phishing-websites dataset) uses. All
computed from the URL string itself, no page fetch required, so this
stays fast and safe to run on anything pasted into the scan box.
"""

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import tldextract

SUSPICIOUS_TLDS = {"zip", "top", "xyz", "click", "gq", "tk", "ml", "cf", "work", "loan"}
SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}

IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


@dataclass
class UrlSignals:
    url: str
    reasons: list[str] = field(default_factory=list)
    score: int = 0

    def add(self, points: int, reason: str) -> None:
        self.score += points
        self.reasons.append(reason)


def analyze_url(url: str) -> UrlSignals:
    signals = UrlSignals(url=url)
    if not url:
        return signals

    parsed = urlparse(url if "://" in url else "http://" + url)
    host = parsed.hostname or ""
    ext = tldextract.extract(host)
    registered_domain = ".".join(part for part in (ext.domain, ext.suffix) if part)

    if parsed.scheme != "https":
        signals.add(1, "not using HTTPS")

    if IP_RE.match(host):
        signals.add(4, "uses a raw IP address instead of a domain name")

    if "@" in url:
        signals.add(4, "contains an @ symbol, a classic redirect trick")

    subdomain_count = len(ext.subdomain.split(".")) if ext.subdomain else 0
    if subdomain_count >= 3:
        signals.add(2, f"has an unusually deep subdomain chain ({subdomain_count} levels)")

    if host.count("-") >= 2:
        signals.add(2, "domain has multiple hyphens, common in typosquatting")

    digits = sum(c.isdigit() for c in ext.domain)
    if ext.domain and digits / max(len(ext.domain), 1) > 0.3:
        signals.add(2, "domain name is unusually digit-heavy")

    if ext.suffix.lower() in SUSPICIOUS_TLDS:
        signals.add(2, f'uses a TLD (".{ext.suffix}") commonly abused for throwaway phishing domains')

    if registered_domain in SHORTENER_DOMAINS:
        signals.add(1, "uses a link shortener, which hides the real destination")

    if len(url) > 90:
        signals.add(1, "unusually long URL, often used to bury the real domain")

    path_and_query = (parsed.path or "") + (parsed.query or "")
    if path_and_query.count("=") >= 4:
        signals.add(1, "has an unusually large number of URL parameters")

    return signals
