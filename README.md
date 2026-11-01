# ThreatScan: Phishing URL Awareness Checker

## Overview
ThreatScan is a lightweight, defensive Python CLI tool designed to inspect URL strings for common structural indicators frequently observed in phishing attacks. The tool performs local string inspection only and does not resolve DNS or initiate network connections.

## Features & Detection Rules
- **Credential Confusion:** Detects `@` symbols in the URL structure.
- **Obfuscated Length:** Identifies URLs exceeding 100 characters.
- **Direct IP Hostname:** Flags raw IPv4 addresses used as hostnames.
- **Subdomain Stacking:** Detects hostnames split into 5 or more dot-separated parts.
- **Punycode / Homograph Marker:** Detects `xn--` indicators.
- **Insecure Transport:** Flags unencrypted `http://` schemes.

## Custom Improvements
1. **Interactive Session Loop:** Repeatedly checks links until given `q` or `exit`.
2. **Crash-Resistant Parsing:** Handles malformed strings gracefully via `try/except`.
3. **Summary Risk Flagging:** Highlights the total count of suspicious clues found.

## How to Run
```bash
python3 threatscan.py
