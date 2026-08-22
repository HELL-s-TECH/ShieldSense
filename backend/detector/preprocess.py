"""Turns a raw scan item (email, link, or file) into the features the classifier scores."""

import re
from dataclasses import dataclass, field

import tldextract

URL_RE = re.compile(r"https?://[^\s<>\"]+")


@dataclass
class Features:
    sender_domain: str | None
    sender_registered_domain: str | None
    text: str
    urls: list[str] = field(default_factory=list)
    attachment_name: str | None = None
    attachment_extensions: list[str] = field(default_factory=list)


def _registered_domain(domain: str) -> str:
    """paypa1-secure.com -> paypa1-secure.com ; mail.yourcompany.com -> yourcompany.com"""
    ext = tldextract.extract(domain)
    return ".".join(part for part in (ext.domain, ext.suffix) if part)


def preprocess(item: dict) -> Features:
    sender_email = (item.get("sender_email") or "").strip().lower()
    sender_domain = sender_email.split("@")[-1] if "@" in sender_email else None

    subject = item.get("subject") or ""
    body = item.get("body") or ""
    link = item.get("link") or ""
    text = " ".join([subject, body, link]).strip()

    urls = URL_RE.findall(text)
    if link and link not in urls:
        urls.append(link)
    # a bare domain typed into the manual scan box, e.g. "accounts-secure-verify.com"
    if link and not urls and "." in link:
        urls.append("http://" + link)

    attachment_name = item.get("attachment")
    attachment_extensions = []
    if attachment_name:
        attachment_extensions = [p.lower() for p in attachment_name.split(".")[1:]]

    return Features(
        sender_domain=sender_domain,
        sender_registered_domain=_registered_domain(sender_domain) if sender_domain else None,
        text=text.lower(),
        urls=urls,
        attachment_name=attachment_name,
        attachment_extensions=attachment_extensions,
    )
