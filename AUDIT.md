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
