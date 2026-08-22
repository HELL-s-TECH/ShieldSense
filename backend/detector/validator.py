"""Catches input that isn't actually a link, email, or file before it
reaches the classifier — so something like "rtoortn" gets told to try
again instead of coming back with a confident (and meaningless) "safe".
"""

from detector.preprocess import Features
from detector.reasoner import call_anthropic, call_groq, call_xai, resolve_provider

REJECTION_SYSTEM_PROMPT = (
    "You are ShieldSense, a security scanning agent. The user submitted something "
    "that doesn't look like a link, email, or file to scan. In one short, friendly "
    "sentence, tell them you need a real link, pasted email text, or an attached "
    "file, and ask them to try again. Don't lecture, don't apologize excessively."
)


def assess_input(features: Features, raw_link: str | None, raw_email_text: str | None) -> str | None:
    """Returns None if the input looks scannable, or a short reason if not.

    Checked against what the caller actually submitted (not the
    auto-generated placeholder subject like "Manual link scan"), so a
    garbage `link` field doesn't slip through just because *some* prose
    text happens to be present.
    """
    if features.attachment_name:
        return None  # a file was attached — that's enough on its own

    if raw_link is not None:
        # they meant to submit a link; if nothing URL-shaped came out of it,
        # it wasn't actually a link.
        return None if features.urls else "doesn't look like a valid link"

    if raw_email_text is not None:
        text = raw_email_text.strip()
        words = text.split()
        if len(words) <= 2 and len(text) < 25:
            return "too short, and not shaped like a link, email, or recognizable text"
        return None

    return None


def invalid_input_message(raw_text: str) -> str:
    resolved = resolve_provider()
    if resolved:
        provider, api_key = resolved
        user_prompt = f'They submitted: "{raw_text}"'
        try:
            if provider == "groq":
                return call_groq(api_key, user_prompt, system=REJECTION_SYSTEM_PROMPT)
            if provider == "xai":
                return call_xai(api_key, user_prompt, system=REJECTION_SYSTEM_PROMPT)
            return call_anthropic(api_key, user_prompt, system=REJECTION_SYSTEM_PROMPT)
        except Exception:
            pass

    return "That doesn't look like a link, email, or file — paste one of those in and try again."
