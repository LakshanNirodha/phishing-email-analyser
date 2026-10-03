"""
ai_layer.py
This file adds the AI explanation layer (v2).

The rule engine (rules.py) already finds WHAT is suspicious and gives a score.
This file takes those findings and asks an AI model to write a short,
clear, plain-English paragraph explaining WHY it matters, the same way a
human SOC analyst would summarise a finding for someone non-technical.

Uses Google Gemini (free tier available, no card needed to get started) as
the AI model. If no API key is set up yet, this file falls back to a simple
template-based explanation instead of crashing, so the tool still works
while you're getting your API key ready.
"""

import os

try:
    from google import genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False


def generate_ai_explanation(email_text: str, flags: list, score: int, risk_level: str) -> str:
    """
    Asks the AI model to explain the result in plain English.
    Falls back to a simple template if no API key is configured yet.
    """
    api_key = os.environ.get("GEMINI_API_KEY")

    if not GEMINI_AVAILABLE or not api_key:
        return _fallback_explanation(flags, score, risk_level)

    flags_text = "\n".join(f"- {flag}" for flag in flags) if flags else "No rule-based flags were triggered."

    prompt = f"""You are a cyber security analyst explaining a phishing risk result to a
non-technical office worker. Be clear, calm, and plain-English. Keep it to 2-4 sentences.

Risk score: {score}/100 ({risk_level})

Flags detected by the rule engine:
{flags_text}

Write a short explanation of why this email was scored this way, and one clear
recommendation for what the reader should do next. Do not repeat the flags list
word for word, synthesise them into a natural explanation."""

    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model="gemini-3.8-flash",
            contents=prompt,
        )
        return response.text.strip()
    except Exception as e:
        # If the API call fails for any reason (no internet, bad key, etc),
        # don't crash the whole tool, just fall back to the template version.
        return _fallback_explanation(flags, score, risk_level) + \
            f"\n\n(AI explanation unavailable right now: {e})"


def _fallback_explanation(flags: list, score: int, risk_level: str) -> str:
    """
    A simple, rule-based explanation used when the AI API is not available.
    This keeps the tool fully working even without an API key.
    """
    if not flags:
        return ("No suspicious patterns were detected by the rule checks. "
                "This does not guarantee the email is safe, only that none "
                "of the current rules were triggered.")

    count = len(flags)
    return (
        f"This email was scored {score}/100 ({risk_level}) because {count} "
        f"separate warning sign{'s' if count != 1 else ''} were found. "
        "Seeing multiple signs together is a stronger indicator than any single "
        "one on its own. Treat this email with caution, do not click any links "
        "or reply with personal information, and verify the sender through a "
        "separate, trusted channel if unsure."
    )
