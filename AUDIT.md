# Portfolio audit — 17–18 October 2026

Baseline: `83494f78adcbe35eb39c800d7c89990ad65363ce`.

## Confirmed fixes

1. The certificate helper previously always used port 443. It now uses the selected HTTPS port, retaining 443 as default.
2. HTTP downloads previously had no body-size bound. Decoded content is now streamed in 64 KiB chunks, rejected above 2 MiB, and closed after completion, redirects, excess data, or read errors.

TLS validation remains enabled. Redirects remain bounded and revalidated. No live suspicious-site scan was used in verification.

## Evidence

- Local Python 3.12.14 compilation passed.
- All **17 offline tests passed**: nine existing URL/public-target cases and eight new HTTP/TLS regressions. Network operations are mocked where exercised.
- Published `app.py` and `tests/test_network_analysis.py` were compared against the locally tested files and matched exactly.
- GitHub Actions passed with the expanded suite on Python 3.11 and 3.12; run `39057057045` is an observed successful result.
- CI uses read-only repository permissions, pinned actions, and dependency installation before application imports.

## Remaining limits

DNS validation and connection remain separate, leaving a DNS-rebinding gap. Read timeouts are not an overall scan deadline. A body cap is not a global memory limit. No labeled-benchmark accuracy, full GUI validation, live-network audit, or real application screenshot is claimed.

## Independent recheck — 20 November 2026

Baseline: `ae553afa16db21e9a6a804a095ae82ad3a80a02c`. Python 3.12.14.

- Reinstalled the declared dependencies in an isolated virtual environment. Baseline compilation and all 17 existing offline tests passed.
- Found a high-priority verdict problem: a failed fetch adds 15 points, so otherwise quiet static checks can still produce LOW RISK without inspecting a webpage. Failed requests, HTTP error pages and unsupported non-HTML responses now produce INCOMPLETE, preserving findings and the heuristic score. The GUI status text reflects incomplete results.
- Added five regression methods (including two content/status subcases). All 22 tests pass after the fix, including blocked targets and successful HTML behavior.
- `pip-audit -r requirements.txt` found no known vulnerabilities in the currently resolved application dependency set. The first whole-environment audit flagged the preinstalled pip bootstrap tool; pip was upgraded in the isolated test environment, and the README now instructs upgrading it before installation. This was not an application runtime vulnerability finding.
- No real phishing website was contacted. GUI screenshots, live network behavior and labeled detection accuracy remain unverified in this audit.

Remaining medium-priority issues: DNS validation is separate from connection establishment; no overall scan deadline; repeated Enter can start another worker despite a disabled scan button, and the UI does not attach a generation ID to returned results. These need isolated regression coverage before further changes. Dependency ranges remain broad rather than a complete reproducibility lock. No source license was added.
