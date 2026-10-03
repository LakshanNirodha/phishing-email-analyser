"""
main.py
This is the file you actually run. It:
 1. Asks you for an email (paste it, or load it from a file)
 2. Runs every rule from rules.py against it
 3. Adds up the points into one risk score
 4. Sends the findings to the AI layer for a plain-English explanation
 5. Prints a clear report

Run it with:  python main.py
"""

import os
from rules import ALL_RULES, check_masked_link
from ai_layer import generate_ai_explanation
from decode_utils import decode_email
from ioc_utils import extract_defanged_iocs
from feedback_log import log_result
from ip_lookup import lookup_ips_in_text
from language_utils import detect_language, translate_to_english
from qr_utils import extract_qr_links


def get_risk_level(score: int) -> str:
    """Turns a number into a simple word, easier for a non-technical person to read."""
    if score >= 60:
        return "HIGH RISK"
    elif score >= 30:
        return "MEDIUM RISK"
    elif score > 0:
        return "LOW RISK"
    else:
        return "NO OBVIOUS SIGNS"


def get_recommended_action(risk_level: str) -> str:
    """
    Turns the risk level into a plain-English "what should I do next"
    instruction, the same way real email security tools (e.g. Barracuda
    Sentinel, Microsoft Defender) add a clear action line under their
    alert, not just a raw score. This tool only advises, it never deletes,
    blocks, or reports anything automatically, a real person always makes
    the final call.
    """
    if risk_level == "HIGH RISK":
        return (
            "Do not click any links or open any attachments in this email. "
            "Do not reply to it. Report it to your IT/security team right "
            "away, then delete it once they confirm."
        )
    elif risk_level == "MEDIUM RISK":
        return (
            "Treat this email with caution. Do not click links or open "
            "attachments yet. Verify the sender through another channel "
            "(e.g. call them, or check their real website) before taking "
            "any action it asks for."
        )
    elif risk_level == "LOW RISK":
        return (
            "A few minor warning signs were found. It may still be "
            "legitimate, but double-check the sender's address and any "
            "links before clicking."
        )
    else:
        return (
            "No red flags were found by the current rules. This does not "
            "guarantee the email is 100% safe, no tool can promise that, "
            "so stay alert, especially with links or attachments."
        )


def analyse_email(
    email_text: str, raw_text: str = None, source: str = "cli", qr_image_bytes: bytes = None
) -> dict:
    """
    Runs every rule in rules.py against the email text.
    Each rule only needs the parts of the email it cares about, but for this
    simple version we just pass the whole email text to every rule, since our
    rules use regex to find what they need inside it.

    raw_text (the original pasted text, before HTML was stripped out) is
    passed separately to check_masked_link, which needs to see the real
    <a href="..."> tags that the normal decoding step removes.

    source ("cli" or "web") is only used to tag the feedback log entry,
    see feedback_log.py, it has no effect on the detection itself.

    qr_image_bytes (optional) is the raw bytes of an uploaded QR code image.
    If given, any link hidden inside it is extracted and checked the exact
    same way as a normal link pasted in the email text, so a scammer can't
    use a QR code image to dodge the link checks.
    """
    total_score = 0
    flags = []
    language_notice = None

    # If a QR code image was provided, pull out any link(s) hidden inside
    # it and add them into the text being checked, so the existing
    # suspicious-link rule (shortened links, raw IP links, etc) also
    # covers links that only exist as a QR code, not as normal text.
    qr_links = extract_qr_links(qr_image_bytes) if qr_image_bytes else []
    if qr_links:
        qr_text = " ".join(qr_links)
        email_text = email_text + "\n\n[Link found inside QR code image]: " + qr_text

    # Our rule phrases are all written in English, so a phishing email in
    # another language would otherwise score 0 and look "safe". Detect the
    # language first, and if it isn't English, translate a copy to English
    # so the same rules can still catch the same scam patterns.
    text_for_rules = email_text
    lang_code, lang_name = detect_language(email_text)
    if lang_code and lang_code != "en":
        translated = translate_to_english(email_text, lang_code)
        if translated:
            text_for_rules = translated
            language_notice = (
                f"This email appears to be written in {lang_name}. It was "
                f"automatically translated to English so the checks below "
                f"could run on it (machine translation may not be perfect)."
            )
        else:
            language_notice = (
                f"This email appears to be written in {lang_name}, but "
                f"automatic translation wasn't available right now (for "
                f"example, no internet connection). The checks below ran on "
                f"the original text, so phishing phrases written in that "
                f"language may have been missed."
            )

    for rule_function in ALL_RULES:
        points, reason = rule_function(text_for_rules)
        if points > 0:
            total_score += points
            flags.append(reason)

    if raw_text:
        points, reason = check_masked_link(raw_text)
        if points > 0:
            total_score += points
            flags.append(reason)

    total_score = min(total_score, 100)  # cap the score at 100
    risk_level = get_risk_level(total_score)
    recommended_action = get_recommended_action(risk_level)

    # Pull out any links/IP addresses and defang them, standard real SOC
    # analyst practice so they're safe to paste into a report or ticket.
    search_text = (raw_text or "") + " " + email_text
    indicators = extract_defanged_iocs(search_text)

    # Look up where any sender IP addresses are actually located/registered.
    # If there's no internet access, or no real IPs in the email, this just
    # comes back as an empty list, it never crashes the rest of the tool.
    origin_lookups = lookup_ips_in_text(search_text)

    print("\nThinking about this one...")  # lets the user know the AI call is happening
    explanation = generate_ai_explanation(email_text, flags, total_score, risk_level)

    result = {
        "score": total_score,
        "risk_level": risk_level,
        "flags": flags,
        "explanation": explanation,
        "indicators": indicators,
        "recommended_action": recommended_action,
        "origin_lookups": origin_lookups,
        "language_notice": language_notice,
        "qr_links": qr_links,
    }

    log_result(result, source=source)

    return result


def print_report(result: dict):
    print("\n" + "=" * 50)
    print(f"RISK SCORE: {result['score']} / 100   ->  {result['risk_level']}")
    print("=" * 50)

    if result.get("language_notice"):
        print(f"\nLANGUAGE NOTE: {result['language_notice']}")

    if result.get("qr_links"):
        print("\nQR CODE FOUND:")
        for i, link in enumerate(result["qr_links"], start=1):
            print(f"  {i}. {link}")
        print("  (This link was checked the same way as any other link in the email.)")

    if result["flags"]:
        print("\nReasons this email was flagged:")
        for i, flag in enumerate(result["flags"], start=1):
            print(f"  {i}. {flag}")
    else:
        print("\nNo suspicious patterns were found by the rule checks.")
        print("(This does not guarantee the email is safe, it only means")
        print(" none of the current rules were triggered.)")

    print("\nAI EXPLANATION:")
    print(result["explanation"])

    print("\nWHAT SHOULD I DO?")
    print(result["recommended_action"])

    if result.get("indicators"):
        print("\nINDICATORS FOUND (defanged, safe to paste into a report):")
        for i, ioc in enumerate(result["indicators"], start=1):
            print(f"  {i}. {ioc}")

    if result.get("origin_lookups"):
        print("\nORIGIN LOOKUP (where the sender's IP address is registered):")
        for i, origin in enumerate(result["origin_lookups"], start=1):
            print(
                f"  {i}. {origin['ip']} -> {origin['city']}, {origin['country']} "
                f"(ISP/organisation: {origin['isp']})"
            )

    print()


def load_email_from_file(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def paste_email_from_terminal() -> str:
    print("Paste the email text below (headers + body together).")
    print("When finished, type END on its own line and press Enter.\n")
    lines = []
    while True:
        line = input()
        if line.strip() == "END":
            break
        lines.append(line)
    return "\n".join(lines)


def main():
    print("Phishing Email Analyser (v2 - rule engine + AI explanation)")
    print("1. Paste an email directly")
    print("2. Load an email from the sample_emails folder")
    choice = input("Choose 1 or 2: ").strip()

    if choice == "2":
        print("\nAvailable sample files:")
        files = sorted(os.listdir("sample_emails"))
        for i, fname in enumerate(files, start=1):
            print(f"  {i}. {fname}")
        file_choice = input("Type the number of the file to analyse: ").strip()
        try:
            chosen_file = files[int(file_choice) - 1]
        except (ValueError, IndexError):
            print("Invalid choice.")
            return
        email_text = load_email_from_file(os.path.join("sample_emails", chosen_file))
    else:
        email_text = paste_email_from_terminal()

    # Keep the original pasted text (raw_text) before decoding, some checks
    # need to see it exactly as pasted.
    raw_text = email_text

    # Decode the email (unscrambles encoded text like =?us-ascii?Q?...?=
    # back into normal readable words) before running the checks on it.
    email_text = decode_email(email_text)

    # Optional: also check a QR code image (e.g. a screenshot of a QR code
    # from the email), if the user has one.
    qr_image_bytes = None
    has_qr = input("\nDo you also want to check a QR code image? (y/n): ").strip().lower()
    if has_qr == "y":
        qr_path = input("Type the path to the QR code image file: ").strip().strip('"')
        try:
            with open(qr_path, "rb") as f:
                qr_image_bytes = f.read()
        except Exception as e:
            print(f"Couldn't read that image file ({e}), continuing without it.")

    result = analyse_email(email_text, raw_text=raw_text, qr_image_bytes=qr_image_bytes)
    print_report(result)


if __name__ == "__main__":
    main()
