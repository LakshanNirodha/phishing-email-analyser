"""
decode_utils.py
Real emails are often stored in an encoded format internally (quoted-printable
or base64), so special characters survive being sent across the internet.
That's why pasting a raw email sometimes shows scrambled text like:
=?us-ascii?Q?bXsOoevAPZefDaT8w+L0sIdd?=

This file unscrambles that back into normal, readable text before our rules
in rules.py try to check it. Python's built-in "email" library already knows
how to do this properly, so we use that instead of writing our own decoder.
"""

from email import message_from_string
from email.header import decode_header
import re


def decode_email(raw_text: str) -> str:
    """
    Takes raw pasted email text (which may or may not be encoded) and
    returns a clean, readable version: headers + plain body text.

    If the text isn't a real encoded email (like our simple sample .txt
    files), this safely falls back to returning the original text
    unchanged, so nothing breaks.
    """
    try:
        msg = message_from_string(raw_text)

        # Decode the headers we care about (From, Subject), which can also
        # be encoded the same way as the body.
        decoded_headers = []
        for header_name in ("From", "To", "Subject", "Reply-To", "Return-Path"):
            value = msg.get(header_name)
            if value:
                decoded_headers.append(f"{header_name}: {_decode_header_value(value)}")

        # Pull out the readable body text.
        body_text = _extract_body(msg)

        combined = "\n".join(decoded_headers) + "\n\n" + body_text

        # If decoding produced basically nothing useful, fall back to the
        # original text rather than losing information.
        if len(combined.strip()) < 10:
            return raw_text

        return combined

    except Exception:
        # Any parsing problem: don't crash the tool, just use the original text.
        return raw_text


def _decode_header_value(value: str) -> str:
    """Decodes an encoded header like '=?us-ascii?Q?...?=' into plain text."""
    parts = decode_header(value)
    decoded = []
    for text, encoding in parts:
        if isinstance(text, bytes):
            decoded.append(text.decode(encoding or "utf-8", errors="ignore"))
        else:
            decoded.append(text)
    return "".join(decoded)


def _extract_body(msg) -> str:
    """
    Pulls the plain-text body out of a (possibly multipart) email message.
    Prefers plain text; falls back to HTML with tags stripped if that's
    all that's available.
    """
    plain_text = None
    html_text = None

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if part.get_content_disposition() == "attachment":
                continue  # skip attachments, not relevant to text analysis

            payload = part.get_payload(decode=True)  # this does the actual decoding
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="ignore")

            if content_type == "text/plain" and plain_text is None:
                plain_text = text
            elif content_type == "text/html" and html_text is None:
                html_text = text
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="ignore")
            if msg.get_content_type() == "text/html":
                html_text = text
            else:
                plain_text = text

    if plain_text:
        return plain_text
    if html_text:
        return _strip_html_tags(html_text)
    return ""


def _strip_html_tags(html: str) -> str:
    """A simple HTML tag remover, good enough for v1. Not a full HTML parser."""
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"\s+", " ", text)
    return text.strip()
