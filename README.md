# PhishGuard — Heuristic Phishing Website Analyzer

A Python desktop proof of concept for examining URLs and page features associated with phishing risk. The CustomTkinter GUI displays a heuristic risk score and the individual checks that contributed to it.

> **Important:** This is a rule-based educational tool, **not an AI/ML model**, a verified malware scanner, or a guarantee that a website is safe. A low score does not mean that a website is trustworthy. Do not open links or enter credentials based only on this result.

## Features

- URL signals: suspicious characters, length, IP/domain structure and keywords
- DNS and TLS certificate checks on relevant hosts
- Optional HTTP(S) fetch, redirect and page-content heuristics
- Findings panel with severity and score breakdown
- Asynchronous scanning to keep the desktop GUI responsive
- Refuses local/private targets as a basic risk reduction measure

## Stack

Python 3.9+, CustomTkinter, Requests, BeautifulSoup, tldextract, python-whois (optional at runtime).

## Run locally

```bash
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

For macOS/Linux activate with `source .venv/bin/activate` instead. GUI requires a graphical desktop and active internet connection for external checks.

## Offline tests

```bash
python -m unittest discover -s tests -v
```

These tests cover input/target safety checks, **not** accuracy against a labeled phishing benchmark. Full GUI and live-network validation were not performed in this packaging pass.

## Security and limitations

- Use **only URLs you are authorized to test**. Fetching untrusted sites still involves some risk.
- TLS verification is not bypassed when an HTTPS certificate fails.
- Non-public IPs and explicit local hostnames are blocked before requests and at redirect hops. **DNS rebinding is not fully prevented** because DNS validation and connection occur separately; do not deploy this local desktop scanner as an open web API.
- Scores are **hand-designed heuristics**, not statistically calibrated probabilities or validated accuracy metrics.
- Page content analysis can produce false positives and false negatives. Some sites may block automated requests.
- Avoid scanning suspicious URLs containing personal tokens or credentials in query strings.

## Author and provenance

**Project type:** Personal project. **Role:** Sole Developer (Raj2003-bubt), as stated by the developer.

The project's earlier source was hosted in [Sakib-183/PhishGuard--Advanced-Phishing-Website-Detector](https://github.com/Sakib-183/PhishGuard--Advanced-Phishing-Website-Detector); this portfolio repository remains a fork to preserve transparent GitHub history. The current portfolio version also includes documentation, tests, and defensive code improvements. The upstream hosting location is not itself a claim of co-authorship.

**License:** No new license is asserted in this repository; obtain appropriate permission before reusing or redistributing third-party components.
