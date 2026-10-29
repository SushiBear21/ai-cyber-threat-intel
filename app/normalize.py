import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.collect_epss import validate_response
from app.collect_kev import validate_catalog


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def fingerprint(value):
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

    return hashlib.sha256(encoded).hexdigest()


def load_snapshot(folder, filename):
    folder = Path(folder)
    manifest = json.loads(
        (folder / "manifest.json").read_text(encoding="utf-8")
    )

    if not isinstance(manifest, dict):
        raise ValueError("Manifest must be an object.")

    if manifest.get("raw_file") != filename:
        raise ValueError("Unexpected raw filename in manifest.")

    raw_path = folder / filename
    if raw_path.stat().st_size > 20 * 1024 * 1024:
        raise ValueError("Saved snapshot exceeds size limit.")

    raw = raw_path.read_bytes()
    actual_hash = hashlib.sha256(raw).hexdigest()

    if actual_hash != manifest.get("sha256"):
        raise ValueError("Snapshot hash does not match manifest.")

    if manifest.get("bytes") != len(raw):
        raise ValueError("Snapshot byte count does not match manifest.")

    for field in ("source", "requested_url", "collected_at"):
        if not isinstance(manifest.get(field), str) or not manifest[field]:
            raise ValueError(f"Missing provenance field: {field}")

    return json.loads(raw.decode("utf-8-sig")), manifest


def provenance(manifest):
    return {
        "source": manifest["source"],
        "requested_url": manifest["requested_url"],
        "collected_at": manifest["collected_at"],
        "raw_sha256": manifest["sha256"],
    }


def normalize_findings(kev, epss, requested_cves):
    validate_catalog(kev)
    validate_response(epss, requested_cves)

    requested = set(requested_cves)
    epss_by_cve = {
        record["cve"]: record
        for record in epss["data"]
    }

    findings = []

    for record in kev["vulnerabilities"]:
        cve = record["cveID"]
        score = epss_by_cve.get(cve)

        if score is not None:
            enrichment = {
                "status": "available",
                "probability": float(score["epss"]),
                "percentile": float(score["percentile"]),
                "score_date": score["date"],
            }
        else:
            enrichment = {
                "status": (
                    "requested_missing"
                    if cve in requested
                    else "not_requested"
                ),
                "probability": None,
                "percentile": None,
                "score_date": None,
            }

        findings.append({
            "cve_id": cve,
            "vendor": record["vendorProject"].strip(),
            "product": record["product"].strip(),
            "title": record["vulnerabilityName"].strip(),
            "description": record["shortDescription"].strip(),
            "required_action": record["requiredAction"].strip(),
            "kev": {
                "listed": True,
                "date_added": record["dateAdded"],
                "source_due_date": record["dueDate"],
                "ransomware_campaign_use": record.get(
                    "knownRansomwareCampaignUse"
                ),
                "notes": record.get("notes"),
            },
            "epss": enrichment,
            "asset_applicability": "not_assessed",
        })

    # Duplicate CVEs are rejected by validation, not silently overwritten.
    return sorted(findings, key=lambda item: item["cve_id"])


def build_dataset(kev_folder, epss_folder):
    kev, kev_manifest = load_snapshot(kev_folder, "catalog.json")
    epss, epss_manifest = load_snapshot(epss_folder, "response.json")

    requested = epss_manifest.get("requested_cves")
    if (
        not isinstance(requested, list)
        or not requested
        or any(not isinstance(cve, str) for cve in requested)
        or len(requested) != len(set(requested))
    ):
        raise ValueError("Invalid requested CVEs in EPSS manifest.")

    findings = normalize_findings(kev, epss, requested)

    # Recheck metadata used to describe these source snapshots.
    if kev_manifest.get("catalog_version") != kev["catalogVersion"]:
        raise ValueError("KEV manifest version mismatch.")

    if kev_manifest.get("record_count") != len(findings):
        raise ValueError("KEV manifest record count mismatch.")

    actual_missing = sorted(
        set(requested) - {item["cve"] for item in epss["data"]}
    )
    if epss_manifest.get("missing_cves") != actual_missing:
        raise ValueError("EPSS manifest missing-CVE mismatch.")

    kev_ids = {item["cve_id"] for item in findings}
    unmatched_epss = sorted(
        item["cve"]
        for item in epss["data"]
        if item["cve"] not in kev_ids
    )

    counts = {
        status: sum(
            finding["epss"]["status"] == status
            for finding in findings
        )
        for status in ("available", "requested_missing", "not_requested")
    }

    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources": {
            "kev": provenance(kev_manifest),
            "epss": provenance(epss_manifest),
        },
        "kev_catalog_version": kev["catalogVersion"],
        "kev_source_date_released": kev["dateReleased"],
        "epss_requested_cves": sorted(requested),
        "epss_cves_outside_kev_snapshot": unmatched_epss,
        "finding_count": len(findings),
        "epss_coverage": counts,
        # Excludes run timestamps and provenance.
        "findings_sha256": fingerprint(findings),
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kev-run", required=True)
    parser.add_argument("--epss-run", required=True)
    args = parser.parse_args()

    try:
        dataset = build_dataset(args.kev_run, args.epss_run)

        run_id = (
            datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            + "-"
            + uuid4().hex[:8]
        )

        folder = PROJECT_ROOT / "data/processed" / run_id
        folder.mkdir(parents=True, exist_ok=False)
        output = folder / "findings.json"
        output.write_text(
            json.dumps(dataset, indent=2, allow_nan=False),
            encoding="utf-8",
        )

        print(f"PASS: normalized {dataset['finding_count']} findings")
        for status, count in dataset["epss_coverage"].items():
            print(f"EPSS {status}: {count}")

        print(
            "EPSS records outside KEV snapshot:",
            len(dataset["epss_cves_outside_kev_snapshot"]),
        )
        print(f"Findings SHA-256: {dataset['findings_sha256']}")
        print(f"Saved to: {output}")

    except (OSError, ValueError, KeyError, TypeError) as error:
        print(
            f"Normalization failed: {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())