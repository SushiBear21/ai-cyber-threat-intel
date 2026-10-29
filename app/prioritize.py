import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.normalize import PROJECT_ROOT, fingerprint


POLICY = {
    "version": "exercise-1",
    "kev_points": 50,
    "internet_exposed_points": 25,
    "criticality_points": {"low": 0, "medium": 10, "high": 15},
    "epss_threshold": 0.50,
    "epss_points": 10,
    "bands": {"expedited_review": 85, "elevated_review": 65},
}


def read_json(path):
    path = Path(path)
    if path.stat().st_size > 30 * 1024 * 1024:
        raise ValueError("Input exceeds size limit.")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def save_json(value, filename):
    run_id = (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + uuid4().hex[:8]
    )
    folder = PROJECT_ROOT / "data/processed" / run_id
    folder.mkdir(parents=True, exist_ok=False)
    path = folder / filename
    path.write_text(
        json.dumps(value, indent=2, allow_nan=False),
        encoding="utf-8",
    )
    return path


def verify_priorities(document):
    if document.get("synthetic") is not True:
        raise ValueError("Synthetic dataset required.")

    candidates = document.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        raise ValueError("Candidate list is missing or empty.")

    if fingerprint(candidates) != document.get("candidates_sha256"):
        raise ValueError("Candidate fingerprint mismatch.")

    identifiers = [item["candidate_id"] for item in candidates]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("Duplicate candidate identifiers.")

    return candidates


def prioritize(dataset, assessments):
    findings = dataset["findings"]

    if fingerprint(findings) != dataset.get("findings_sha256"):
        raise ValueError("Normalized findings fingerprint mismatch.")

    if assessments.get("synthetic") is not True:
        raise ValueError("Synthetic assessments required.")

    if (
        assessments.get("input_findings_sha256")
        != dataset["findings_sha256"]
    ):
        raise ValueError("Assessments reference different findings.")

    by_cve = {item["cve_id"]: item for item in findings}
    if len(by_cve) != len(findings):
        raise ValueError("Duplicate finding CVE.")

    rows = []
    seen = set()

    for assessment in assessments["assessments"]:
        if assessment.get("applicability") != "needs_review":
            raise ValueError("Expected needs_review applicability.")

        finding = by_cve[assessment["cve_id"]]
        if finding["kev"].get("listed") is not True:
            raise ValueError("Expected KEV-listed finding.")

        candidate_id = "|".join([
            assessment["cve_id"],
            assessment["asset_id"],
            assessment["component_id"],
        ])
        if candidate_id in seen:
            raise ValueError("Duplicate candidate.")
        seen.add(candidate_id)

        criticality = assessment["business_criticality"]
        if criticality not in POLICY["criticality_points"]:
            raise ValueError("Unknown criticality.")

        exposed = assessment["internet_exposed"]
        if type(exposed) is not bool:
            raise ValueError("Exposure must be boolean.")

        reasons = [{
            "signal": "KEV-listed",
            "points": POLICY["kev_points"],
        }]

        if exposed:
            reasons.append({
                "signal": "Internet-exposed",
                "points": POLICY["internet_exposed_points"],
            })

        reasons.append({
            "signal": f"Business criticality: {criticality}",
            "points": POLICY["criticality_points"][criticality],
        })

        epss = finding["epss"]
        data_gaps = []

        if epss["status"] == "available":
            probability = epss["probability"]
            if (
                type(probability) not in (int, float)
                or not 0 <= probability <= 1
            ):
                raise ValueError("Invalid EPSS probability.")

            if probability >= POLICY["epss_threshold"]:
                reasons.append({
                    "signal": "EPSS probability at least 0.50",
                    "points": POLICY["epss_points"],
                })
        elif epss["status"] in {"not_requested", "requested_missing"}:
            data_gaps.append(f"EPSS: {epss['status']}")
        else:
            raise ValueError("Unknown EPSS status.")

        score = sum(reason["points"] for reason in reasons)
        if score >= 85:
            band = "expedited_review"
        elif score >= 65:
            band = "elevated_review"
        else:
            band = "standard_review"

        rows.append({
            "candidate_id": candidate_id,
            "review_score": score,
            "review_band": band,
            "reasons": reasons,
            "data_gaps": data_gaps,
            "assessment": assessment,
            "finding": finding,
        })

    if not rows:
        raise ValueError("No candidate assessments to prioritize.")

    rows.sort(key=lambda item: (-item["review_score"], item["candidate_id"]))

    return {
        "schema_version": "1.0",
        "synthetic": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "policy": POLICY,
        "input_findings_sha256": dataset["findings_sha256"],
        "input_assessments_sha256": fingerprint(assessments),
        "sources": dataset["sources"],
        "coverage": {
            "normalized_findings": len(findings),
            "candidate_assessments": len(rows),
            "findings_without_rule_match": len(
                assessments["finding_cves_without_rule_match"]
            ),
            "assets_without_rule_match": len(
                assessments["asset_ids_without_rule_match"]
            ),
        },
        "candidates_sha256": fingerprint(rows),
        "candidates": rows,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings", required=True)
    parser.add_argument("--assessments", required=True)
    args = parser.parse_args()

    try:
        result = prioritize(
            read_json(args.findings),
            read_json(args.assessments),
        )
        path = save_json(result, "prioritized.json")

        for item in result["candidates"]:
            print(
                item["candidate_id"],
                item["review_score"],
                item["review_band"],
            )
        print(f"Saved to: {path}")

    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Prioritization failed: {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())