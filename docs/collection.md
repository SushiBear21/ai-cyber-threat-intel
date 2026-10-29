# Intelligence collection

## Source 1: CISA KEV

Publisher: Cybersecurity and Infrastructure Security Agency.

Catalog:
https://www.cisa.gov/known-exploited-vulnerabilities-catalog

Collection endpoint:
https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json

The collector uses CISA's official GitHub mirror.
The mirror may briefly lag the canonical website feed.

## Run

From the repository root:

    .\.venv\Scripts\python.exe .\app\collect_kev.py

Each successful run creates a separate directory under data/raw/kev/
containing:
- catalog.json: original downloaded bytes.
- manifest.json: source URLs, UTC collection timestamp, catalog
  version, source release date, record count, byte count, and SHA-256.

Raw downloads are excluded from Git.

## Validation

The collector checks:
- Top-level object and nonempty catalog metadata.
- Nonempty vulnerability list.
- Declared count matches record count.
- CVE identifiers have the expected format and are unique.
- Required text fields are present and nonempty.
- Record dates can be parsed.

These are basic application checks, not full JSON Schema validation.
Source release-date parsing and freshness enforcement remain future work.

Downloads have a 30-second timeout and a 20 MiB size limit.
Automatic retries and partial-run recovery are not implemented yet.

## Verified collection

- Catalog version: 2026.10.28
- Source release: 2026-10-28T19:00:04.8077Z
- Collection timestamp: 2026-10-29T00:13:52Z
- Records: 1,762
- SHA-256:
  c72e8b7751209e7575ed777439e3f4e9295ba86b4edf5d52730959d8bf9bfe64

The saved file matched the manifest hash.
Seven local validation tests passed.

## Interpretation

KEV inclusion identifies a vulnerability cataloged by CISA as
known exploited. It does not prove that a particular asset is affected
or compromised.

Absence from KEV does not establish that a vulnerability is safe
or has never been exploited.

The SHA-256 comparison verifies consistency with our collection
record; it does not independently authenticate the publisher.