"""
ioc_utils.py

IOC = "Indicator of Compromise". In real security work, when an analyst
finds a suspicious link, domain, or IP address, they don't just leave it as
a normal clickable link in their notes or report, that's dangerous, someone
could click it by accident later. Instead they "defang" it: change it just
enough that it's still readable, but can't be clicked or opened by accident.

This is a standard, real SOC analyst practice (also taught directly in
TryHackMe's Phishing Analysis module: "Hyperlinks and IP addresses should
be defanged"). This file pulls out the suspicious links/domains found in an
email and prints them in this safe, defanged format, like a real analyst
would write in an incident report.

Example:
  Original:  http://suspicious-domain.com
  Defanged:  hxxp[://]suspicious-domain[.]com
"""

import re


def defang(value: str) -> str:
    """Makes one link or domain unsafe to click, but still readable."""
    defanged = value.replace("http://", "hxxp[://]").replace("https://", "hxxps[://]")
    defanged = defanged.replace(".", "[.]")
    return defanged


def extract_defanged_iocs(email_text: str) -> list:
    """
    Finds every link (http/https URL) and raw IP address mentioned in the
    email, and returns them already defanged, ready to safely paste into a
    report, a ticket, or share with a colleague.
    """
    urls = re.findall(r"https?://[^\s\)\]\"'<>]+", email_text)
    ip_addresses = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", email_text)

    indicators = []
    seen = set()
    for url in urls:
        if url not in seen:
            seen.add(url)
            indicators.append(defang(url))
    for ip in ip_addresses:
        if ip not in seen:
            seen.add(ip)
            indicators.append(defang(ip))

    return indicators
