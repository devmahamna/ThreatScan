# Test Results - ThreatScan

**Python Version:** Python 3.x (Kali Linux)  
**Operating System:** Kali GNU/Linux  

| # | Input URL | Expected Result | Actual Result | Status |
|---|---|---|---|---|
| 1 | `https://www.example.com/login` | No listed warning signs | No listed warning signs found. This does NOT prove safety. | PASS |
| 2 | `http://192.0.2.10/account` | IP address + HTTP | Uses an IP address; Uses HTTP | PASS |
| 3 | `http://example.com@sample.invalid/login` | @ symbol + HTTP | Contains an @ symbol; Uses HTTP | PASS |
| 4 | `https://a.b.c.d.e.example.invalid/path` | Many hostname segments | Contains many hostname segments/subdomains | PASS |
| 5 | `https://xn--example.invalid/` | Punycode hostname | Contains a punycode-style hostname | PASS |

## Notes
- Verified that static text heuristics trigger without generating outbound HTTP requests.
- Handled empty and malformed string parsing cleanly.
