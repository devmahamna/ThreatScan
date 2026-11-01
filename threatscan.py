"""
ThreatScan - Phishing URL Awareness Checker
Educational tool designed to inspect static URL text for common heuristic red flags.
Defensive learning only. Does NOT connect to or open URLs.
"""

import re
from urllib.parse import urlparse

INFO_MESSAGES = (
    "No URL entered.",
    "Could not identify a hostname.",
    "This text is not a valid URL format.",
    "No listed warning signs found. This does NOT prove safety."
)

def inspect_url(raw_url: str) -> list[str]:
    """Check visible URL text for selected warning signs."""
    url = raw_url.strip()
    findings = []

    if not url:
        return ["No URL entered."]

    # Prepend scheme if missing so urlparse can reliably parse the hostname
    candidate = url if "://" in url else "http://" + url

    # Safe parsing: catches malformed inputs like 'http://[bad'
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return ["This text is not a valid URL format."]

    host = (parsed.hostname or "").lower()

    if not host:
        return ["Could not identify a hostname."]

    # Rule 1: '@' Symbol Detection
    if "@" in candidate:
        findings.append("Contains an @ symbol; inspect carefully (browsers ignore credentials prior to @).")

    # Rule 2: Excessive URL Length
    if len(url) > 100:
        findings.append("Unusually long URL (over 100 characters).")

    # Rule 3: IP Address Hostname
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        findings.append("Uses an IP address instead of a familiar domain name.")

    # Rule 4: Deep Subdomain Stacking
    labels = [part for part in host.split(".") if part]
    if len(labels) >= 5:
        findings.append("Contains many hostname segments/subdomains (5 or more).")

    # Rule 5: Punycode / IDN Homograph Marker
    if "xn--" in host:
        findings.append("Contains a punycode-style hostname (xn--). May mimic legitimate characters.")

    # Rule 6: Insecure Scheme (HTTP)
    if parsed.scheme.lower() == "http":
        findings.append("Uses HTTP (unencrypted). Note: HTTPS alone does not prove trust.")

    # Fallback when no warning signals are triggered
    if not findings:
        findings.append("No listed warning signs found. This does NOT prove safety.")

    return findings

def has_warnings(findings: list[str]) -> bool:
    """Helper to verify if any critical warning signs were flagged."""
    if not findings:
        return False
    return not findings[0].startswith(INFO_MESSAGES)

def main():
    print("=" * 55)
    print(" ThreatScan (by Devender Kumar) - Phishing URL Awareness Checker")
    print(" Text checks only — this program does not open URLs.")
    print("=" * 55)

    while True:
        raw_url = input("\nEnter a sample URL to inspect (or 'q' to quit): ").strip()

        if raw_url.lower() in ("q", "quit", "exit"):
            print("\nExiting ThreatScan. Stay alert online!")
            break

        results = inspect_url(raw_url)

        print("\nResult:")
        for item in results:
            print(f" - {item}")

        if has_warnings(results):
            print(f"\n[!] REVIEW CAREFULLY: {len(results)} warning sign(s) found.")

        print("\nNotice: Never enter passwords or credentials from unexpected links.")

if __name__ == "__main__":
    main()
