"""
ip_lookup.py
This file adds the "domain/IP origin lookup" feature (v4, part 3).

For each real public IP address found in the email (usually in the
headers, from "Received:" lines), this looks up roughly where it's
located in the world and which company/network it belongs to. This is
useful context: a sender IP registered to a well-known email provider
reads very differently to one registered to an unrelated hosting company
in another country.

Uses the free ip-api.com service (no account or API key needed for
personal/non-commercial use, rate-limited to 45 requests per minute). If
a lookup fails for any reason (no internet, rate limit, invalid IP),
that IP is just skipped, it never crashes the rest of the tool.
"""

import re

import requests

IP_API_URL = "http://ip-api.com/json/{ip}"
REQUEST_TIMEOUT_SECONDS = 4
MAX_LOOKUPS_PER_EMAIL = 5  # keeps us well under the free rate limit


def extract_ips(text: str) -> list:
    """Finds all IPv4 addresses in the given text, de-duplicated, in order."""
    found = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    seen = []
    for ip in found:
        if ip not in seen:
            seen.append(ip)
    return seen


def _is_private_ip(ip: str) -> bool:
    """
    Quick check for private/local IP ranges (e.g. inside a company's own
    network). These are never worth looking up publicly, they don't mean
    anything outside that company's own network.
    """
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("127.")
        or ip.startswith("0.")
        or bool(re.match(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", ip))
    )


def lookup_ip(ip: str) -> dict:
    """
    Looks up one IP address. Returns a dict with country, city, and isp,
    or None if the lookup failed or the IP is private.
    """
    if _is_private_ip(ip):
        return None

    try:
        response = requests.get(IP_API_URL.format(ip=ip), timeout=REQUEST_TIMEOUT_SECONDS)
        data = response.json()
        if data.get("status") == "success":
            return {
                "ip": ip,
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", "Unknown"),
            }
    except Exception:
        pass
    return None


def lookup_ips_in_text(text: str) -> list:
    """
    Finds every public IP in the given text and looks each one up, capped
    at MAX_LOOKUPS_PER_EMAIL. Returns a list of result dicts, skipping any
    that failed or were private, so the list can safely be empty.
    """
    ips = extract_ips(text)
    results = []
    for ip in ips[:MAX_LOOKUPS_PER_EMAIL]:
        result = lookup_ip(ip)
        if result:
            results.append(result)
    return results
