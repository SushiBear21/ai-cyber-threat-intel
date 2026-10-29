# Normalization and deduplication

## Run

From the repository root:

    .\.venv\Scripts\python.exe -m app.normalize --kev-run PATH_TO_KEV_RUN --epss-run PATH_TO_EPSS_RUN

Each input folder must contain its original response and manifest.

## Input integrity

The loader verifies the saved response's SHA-256 and byte count
against the collection manifest, then validates the source records.

This detects inconsistency with our manifest. It does not independently
authenticate the publisher or protect against coordinated modification
of both the response and manifest.

## Finding model

The output contains one finding per CVE in the selected KEV snapshot.
EPSS enrichment joins by exact CVE identifier.

Duplicate CVEs within a source response are rejected.
Findings are sorted by CVE identifier.

EPSS states:
- available: a returned score was joined.
- requested_missing: requested, but absent from the EPSS response.
- not_requested: outside the selected EPSS lookup.

Missing scores remain null rather than becoming zero.
EPSS records outside the selected KEV snapshot are listed separately;
they do not create KEV-listed findings.

All asset applicability is initially not_assessed.
KEV due dates remain source dates, not fictional-organization deadlines.

## Provenance and repeatability

The dataset records source URLs, collection timestamps, raw hashes,
KEV catalog version, and source release date.
Available EPSS scores retain their score date.

A findings_sha256 fingerprint covers the normalized findings,
excluding output generation time and source provenance.

Identical source content produces identical findings regardless
of KEV input ordering. Score changes alter the findings fingerprint.

Each run writes a separate file under data/processed/.
Generated datasets are excluded from Git.

## Limitations

This is a KEV-led dataset with partial EPSS coverage.
It is not a complete inventory of vulnerabilities.

Historical merge rules, incremental processing, and a persistent
change ledger are not implemented.

Full schema validation, source freshness enforcement, and transactional
output recovery remain future work.

A fingerprint difference indicates changed normalized content;
it does not explain the change or establish its operational significance.