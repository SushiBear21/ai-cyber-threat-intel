import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path
from uuid import uuid4


SOURCE_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/"
    "develop/known_exploited_vulnerabilities.json"
)
MAX_BYTES = 20 * 1024 * 1024
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def validate_catalog(catalog):
    if not isinstance(catalog, dict):
        raise ValueError("Catalog must be a JSON object.")

    for field in ("catalogVersion", "dateReleased"):
        if not isinstance(catalog.get(field), str) or not catalog[field]:
            raise ValueError(f"Missing catalog field: {field}")

    records = catalog.get("vulnerabilities")
    if not isinstance(records, list) or not records:
        raise ValueError("Catalog has no vulnerability records.")

    count = catalog.get("count")
    if type(count) is not int or count != len(records):
        raise ValueError("Catalog count does not match its records.")

    seen = set()
    required_text = (
        "vendorProject",
        "product",
        "vulnerabilityName",
        "shortDescription",
        "requiredAction",
    )

    for record in records:
        if not isinstance(record, dict):
            raise ValueError("Vulnerability record must be an object.")

        cve = record.get("cveID")
        if not isinstance(cve, str) or not re.fullmatch(
            r"CVE-\d{4}-\d{4,}", cve
        ):
            raise ValueError("Invalid CVE identifier.")

        if cve in seen:
            raise ValueError(f"Duplicate CVE: {cve}")
        seen.add(cve)

        for field in required_text:
            value = record.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{cve}: missing {field}")

        for field in ("dateAdded", "dueDate"):
            value = record.get(field)
            if not isinstance(value, str):
                raise ValueError(f"{cve}: missing {field}")
            date.fromisoformat(value)

    return len(records)


def collect():
    request = urllib.request.Request(
        SOURCE_URL,
        headers={
            "User-Agent": "ai-cyber-threat-intel-portfolio/0.1",
            "Accept": "application/json",
        },
    )

    with urllib.request.urlopen(request, timeout=30) as result:
        if result.status != 200:
            raise ValueError("Feed did not return HTTP 200.")

        final_url = result.geturl()
        raw = result.read(MAX_BYTES + 1)

    if len(raw) > MAX_BYTES:
        raise ValueError("Feed exceeds the download size limit.")

    catalog = json.loads(raw.decode("utf-8-sig"))
    count = validate_catalog(catalog)

    collected_at = datetime.now(timezone.utc)
    run_id = (
        collected_at.strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + uuid4().hex[:8]
    )

    folder = PROJECT_ROOT / "data" / "raw" / "kev" / run_id
    folder.mkdir(parents=True, exist_ok=False)

    raw_path = folder / "catalog.json"
    raw_path.write_bytes(raw)

    manifest = {
        "source": "CISA KEV official GitHub mirror",
        "requested_url": SOURCE_URL,
        "retrieved_url": final_url,
        "collected_at": collected_at.isoformat(),
        "catalog_version": catalog["catalogVersion"],
        "source_date_released": catalog["dateReleased"],
        "record_count": count,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "raw_file": raw_path.name,
        "validation": "basic_checks_passed",
    }

    (folder / "manifest.json").write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )

    print(f"PASS: collected and validated {count} KEV records")
    print(f"Catalog version: {catalog['catalogVersion']}")
    print(f"Source release date: {catalog['dateReleased']}")
    print(f"Saved to: {folder}")
    print(f"SHA-256: {manifest['sha256']}")


def main():
    try:
        collect()
    except (
        OSError,
        ValueError,
        urllib.error.URLError,
    ) as error:
        print(
            f"Collection failed: {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())