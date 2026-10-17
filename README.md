# PhishGuard — Heuristic Phishing Website Analyzer

**Inspect the signals behind a website-risk assessment.**

[![Python security checks](https://github.com/Raj2003-bubt/PhishGuard--Advanced-Phishing-Website-Detector/actions/workflows/python-tests.yml/badge.svg)](https://github.com/Raj2003-bubt/PhishGuard--Advanced-Phishing-Website-Detector/actions/workflows/python-tests.yml)

PhishGuard is a personal Python desktop project that examines URLs and returned webpages for heuristic phishing-risk indicators. Its CustomTkinter interface displays individual findings, severity counts, and a capped score so users can inspect which rules influenced the result.

## Problem and motivation

A familiar-looking domain, a login form, or a valid HTTPS certificate alone cannot establish trust. PhishGuard makes common warning signals visible in an educational interface while demonstrating network programming, HTML parsing, defensive input handling, and asynchronous desktop application design.

**A finding is not proof of phishing; a low score is not proof of safety.** There is no validated detection-accuracy claim. This tool does not replace browser protections or professional security software.

## Implemented checks

| Stage | Source-supported analysis |
|---|---|
| URL | Scheme, length, direct IP, subdomains, keywords, shortening domains, punycode, encoded characters, unusual ports, digits, and configured TLD indicators |
| Host | DNS resolution, TLS certificate validation/expiry for domain-based HTTPS URLs, and optional WHOIS creation dates |
| HTTP | Up to five redirects, destination-domain changes, status, content type, and a 2 MiB decoded response limit |
| HTML | Password fields, external/empty/JavaScript form actions, hidden iframes, configured urgency phrases, script patterns, and external script counts |
| Results | Point breakdown, severity filters, and LOW RISK / SUSPICIOUS / HIGH RISK labels |

Rules contribute manually chosen points. Scores are capped at 100, with label thresholds at 25 and 55; these are not probabilities. Legitimate pages can trigger rules.

## Technology and workflow

**Python 3.9+ · CustomTkinter/Tk · Requests · BeautifulSoup · tldextract · python-whois**

1. Normalize and validate the entered HTTP(S) URL.
2. Reject local/private targets before analysis.
3. Run URL, host, HTTP, and HTML checks in a worker thread.
4. Score findings and update the desktop results panel.

`app.py` contains the GUI and analysis; `security_checks.py` isolates URL/public-address checks; `tests/test_security_checks.py` uses mocked DNS. The public-suffix extractor uses its bundled snapshot at initialization. A requested scan contacts external services.

## Install and run

```bash
git clone https://github.com/Raj2003-bubt/PhishGuard--Advanced-Phishing-Website-Detector.git
cd PhishGuard--Advanced-Phishing-Website-Detector
python -m venv .venv
```

Activate with `.venv\Scripts\Activate.ps1` in Windows PowerShell, or `source .venv/bin/activate` on macOS/Linux. Then:

```bash
python -m pip install -r requirements.txt
python app.py
```

A graphical desktop and Tk support are required. Some Linux distributions package Tk separately. External checks need internet access; WHOIS may be missing, rate-limited, or unavailable. Scan only URLs you are authorized to contact.

## Verification

```bash
python -m compileall -q app.py security_checks.py
python -m unittest discover -s tests -v
```

All 17 offline tests pass in the portfolio audit. They cover URL/public-target checks plus bounded response reading, interrupted streams, blocked redirects, redirect limits, TLS failure handling, and custom HTTPS ports. HTTP, DNS, TLS, and WHOIS are mocked where used; tests do not scan websites. Install application dependencies before running the expanded suite. Compilation does not launch the GUI.

GitHub Actions runs these checks independently. This suite does not measure phishing accuracy, exercise the full GUI, or validate every live-network/error path.

## Screenshots

No application screenshot is currently committed. Captures of the actual desktop interface and an authorized scan remain a documentation task; no simulated screenshot is presented as evidence.

## Security boundaries and limitations

- Accepts HTTP(S) without embedded credentials; checks for non-public addresses initially and at redirect hops.
- Keeps HTTPS verification enabled; certificate errors are not retried insecurely.
- DNS validation and connection are separate, leaving a DNS-rebinding gap. Keep this a local desktop tool, not a public scan API.
- Decoded response bodies are limited to 2 MiB and response streams are closed after use. Larger pages are not analyzed; the cap is not a total process-memory guarantee.
- Certificate checks use the selected HTTPS port. DNS checks and later connections are still separate operations.
- HTML is parsed without executing JavaScript, so dynamic content can be missed.
- TLS, domain age, keywords, and page structure are imperfect signals; false positives/negatives are expected.
- Avoid URLs containing private tokens. The target receives the request, and DNS/WHOIS infrastructure may receive lookups.

Future work includes stronger connection-level target binding, end-to-end scan time limits, real GUI captures, and evaluation against a responsibly obtained labeled dataset. These are not current capabilities.

## Author and provenance

Personal project by **Raj2003-bubt**, described by the owner as their implementation. Earlier hosting is preserved through the fork relationship with [Sakib-183/PhishGuard--Advanced-Phishing-Website-Detector](https://github.com/Sakib-183/PhishGuard--Advanced-Phishing-Website-Detector); hosting location alone does not establish co-authorship. Original history and attribution remain intact.

No new license is asserted. Check applicable rights and third-party dependency licenses before redistribution.
