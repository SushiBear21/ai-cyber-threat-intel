# EPSS enrichment source

Publisher: FIRST.
Documentation: https://www.first.org/epss/
API: https://api.first.org/data/v1/epss

## Purpose

EPSS estimates the probability of observed exploitation activity
for a CVE in the next 30 days.

The percentile represents the score's relative ranking.
Neither value establishes whether a particular asset is vulnerable
or compromised.

A low EPSS score does not cancel KEV evidence of known exploitation.
A missing score is recorded as missing, not converted to zero.

## Collection

Run from the repository root:

    .\.venv\Scripts\python.exe -m app.collect_epss --cves CVE-2021-44228 CVE-2023-34362 CVE-2017-0144

This collector accepts 1–10 CVEs per invocation.
The API is used for small lookups. Bulk enrichment will require
FIRST's daily data file rather than repeated API calls.

Each successful run saves under data/raw/epss/:
- response.json: original downloaded bytes.
- manifest.json: URLs, collection timestamp, requested CVEs,
  missing CVEs, score dates, byte count, and SHA-256.

Raw responses are excluded from Git.
Displayed percentages are rounded; original values remain in the response.

## Validation

Checks include:
- Source status is OK and data is a list.
- Returned CVEs were requested and are unique.
- Scores and percentiles are finite numbers between 0 and 1.
- Score dates can be parsed.
- Missing CVEs are listed explicitly.

Score freshness enforcement and full response-schema validation
are not implemented yet.

## Network handling

The shared HTTP helper is currently used by the EPSS collector.
It makes up to three attempts for network timeouts, URL errors,
HTTP 429, and HTTP 500/502/503/504.

Each attempt has a 30-second timeout and a bounded download size.
Numeric Retry-After values up to 30 seconds are respected.
Longer values and HTTP-date Retry-After values stop automatic retries.
Other HTTP errors and oversized responses are not retried.

The KEV collector still uses its original download implementation.

## Verified results

- Three requested CVEs returned successfully.
- Score date: 2026-10-28.
- No missing CVEs in the observed lookup.
- Combined test suite: 22 passing tests.

Retry behavior was tested with simulated failures.
No live rate-limit or server-error test was performed.

The two sources have not yet been joined into normalized findings.
That is Session 4.