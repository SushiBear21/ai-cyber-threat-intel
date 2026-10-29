import argparse
import hashlib
import json
import math
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path
from uuid import uuid4
from app.http_client import download_json_bytes

ENDPOINT = "https://api.first.org/data/v1/epss"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 2 * 1024 * 1024


def validate_response(payload, requested):
    if not isinstance(payload, dict) or payload.get("status") != "OK":
        raise ValueError("EPSS response did not report OK.")

    records = payload.get("data")
    if not isinstance(records, list):
        raise ValueError("EPSS data must be a list.")

    seen = set()

    for record in records:
        if not isinstance(record, dict):
            raise ValueError("EPSS record must be an object.")

        cve = record.get("cve")
        if not isinstance(cve, str) or cve not in requested:
            raise ValueError("Unexpected CVE in EPSS response.")
        if cve in seen:
            raise ValueError("Duplicate CVE in EPSS response.")
        seen.add(cve)

        for field in ("epss", "percentile"):
            value = record.get(field)
            if isinstance(value, bool) or not isinstance(
                value, (str, int, float)
            ):
                raise ValueError(f"{cve}: invalid {field}")

            number = float(value)
            if not math.isfinite(number) or not 0 <= number <= 1:
                raise ValueError(f"{cve}: {field} outside 0–1")

        score_date = record.get("date")
        if not isinstance(score_date, str):
            raise ValueError(f"{cve}: missing score date")
        date.fromisoformat(score_date)

    return sorted(set(requested) - seen)


def collect(cves):
    if not 1 <= len(cves) <= 10:
        raise ValueError("Request 1–10 CVEs for this small lookup.")

    if any(not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve) for cve in cves):
        raise ValueError("Invalid CVE identifier.")

    cves = sorted(set(cves))
    url = ENDPOINT + "?" + urllib.parse.urlencode({
        "cve": ",".join(cves),
        "limit": len(cves),
    })

    raw, final_url = download_json_bytes(url, MAX_BYTES)

    payload = json.loads(raw.decode("utf-8-sig"))
    missing = validate_response(payload, cves)

    collected_at = datetime.now(timezone.utc)
    run_id = (
        collected_at.strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + uuid4().hex[:8]
    )

    folder = PROJECT_ROOT / "data/raw/epss" / run_id
    folder.mkdir(parents=True, exist_ok=False)
    (folder / "response.json").write_bytes(raw)

    manifest = {
        "source": "FIRST EPSS API",
        "requested_url": url,
        "retrieved_url": final_url,
        "collected_at": collected_at.isoformat(),
        "requested_cves": cves,
        "returned_count": len(payload["data"]),
        "missing_cves": missing,
        "score_dates": sorted({
            record["date"] for record in payload["data"]
        }),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "raw_file": "response.json",
        "validation": "basic_checks_passed",
    }

    (folder / "manifest.json").write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )

    print(f"PASS: validated {len(payload['data'])} EPSS records")

    for record in payload["data"]:
        print(
            f"{record['cve']} | "
            f"EPSS: {float(record['epss']):.2%} | "
            f"Percentile: {float(record['percentile']):.2%} | "
            f"Date: {record['date']}"
        )

    print(f"Missing CVEs: {', '.join(missing) if missing else 'none'}")
    print(f"Saved to: {folder}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cves", nargs="+", required=True)
    args = parser.parse_args()

    try:
        collect(args.cves)
    except (OSError, ValueError, RuntimeError, urllib.error.URLError) as error:
        print(
            f"Collection failed: {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())