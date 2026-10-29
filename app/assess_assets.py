import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.normalize import PROJECT_ROOT, fingerprint


def require_text(record, field):
    value = record.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Missing or invalid {field}")
    return value.strip()


def validate_inventory(inventory):
    if (
        not isinstance(inventory, dict)
        or inventory.get("synthetic") is not True
    ):
        raise ValueError("A synthetic inventory is required.")

    assets = inventory.get("assets")
    if not isinstance(assets, list) or not assets:
        raise ValueError("Inventory must contain assets.")

    asset_ids = set()
    component_ids = set()

    for asset in assets:
        if not isinstance(asset, dict):
            raise ValueError("Asset must be an object.")

        asset_id = require_text(asset, "asset_id")
        if asset_id in asset_ids:
            raise ValueError("Duplicate asset ID.")
        asset_ids.add(asset_id)

        require_text(asset, "name")
        require_text(asset, "owner")

        if asset.get("business_criticality") not in {
            "low", "medium", "high"
        }:
            raise ValueError("Invalid business criticality.")

        if type(asset.get("internet_exposed")) is not bool:
            raise ValueError("Exposure must be explicitly true or false.")

        components = asset.get("components")
        if not isinstance(components, list) or not components:
            raise ValueError("Asset must contain components.")

        for component in components:
            if not isinstance(component, dict):
                raise ValueError("Component must be an object.")

            component_id = require_text(component, "component_id")
            if component_id in component_ids:
                raise ValueError("Duplicate component ID.")
            component_ids.add(component_id)

            for field in (
                "component_key", "vendor", "product", "version"
            ):
                require_text(component, field)


def validate_rules(rules):
    if (
        not isinstance(rules, dict)
        or rules.get("synthetic") is not True
    ):
        raise ValueError("Synthetic review rules are required.")

    entries = rules.get("rules")
    if not isinstance(entries, list):
        raise ValueError("Rules must be a list.")

    rule_ids = set()
    pairs = set()

    for rule in entries:
        if not isinstance(rule, dict):
            raise ValueError("Rule must be an object.")

        rule_id = require_text(rule, "rule_id")
        cve = require_text(rule, "cve_id")
        component_key = require_text(rule, "component_key")
        require_text(rule, "basis")

        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
            raise ValueError("Invalid CVE in rule.")

        if rule_id in rule_ids:
            raise ValueError("Duplicate rule ID.")
        rule_ids.add(rule_id)

        pair = (cve, component_key)
        if pair in pairs:
            raise ValueError("Duplicate CVE/component rule.")
        pairs.add(pair)


def assess_findings(findings, inventory, rules):
    validate_inventory(inventory)
    validate_rules(rules)

    if not isinstance(findings, list):
        raise ValueError("Findings must be a list.")

    findings_by_cve = {}
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("Finding must be an object.")

        cve = require_text(finding, "cve_id")
        if cve in findings_by_cve:
            raise ValueError("Duplicate finding CVE.")
        findings_by_cve[cve] = finding

    component_index = {}
    for asset in inventory["assets"]:
        for component in asset["components"]:
            key = component["component_key"].strip()
            component_index.setdefault(key, []).append(
                (asset, component)
            )

    assessments = []
    rules_without_findings = []
    rules_without_components = []

    for rule in rules["rules"]:
        cve = rule["cve_id"].strip()
        key = rule["component_key"].strip()

        if cve not in findings_by_cve:
            rules_without_findings.append(rule["rule_id"])
            continue

        matches = component_index.get(key, [])
        if not matches:
            rules_without_components.append(rule["rule_id"])

        for asset, component in matches:
            assessments.append({
                "cve_id": cve,
                "asset_id": asset["asset_id"],
                "asset_name": asset["name"],
                "owner": asset["owner"],
                "component_id": component["component_id"],
                "component_key": key,
                "inventory_version": component["version"],
                "business_criticality": asset["business_criticality"],
                "internet_exposed": asset["internet_exposed"],
                "applicability": "needs_review",
                "match_method": "explicit_synthetic_review_rule",
                "rule_id": rule["rule_id"],
                "basis": rule["basis"],
                "version_check": "not_performed",
                "patch_status": "not_assessed",
            })

    assessments.sort(
        key=lambda item: (
            item["cve_id"],
            item["asset_id"],
            item["component_id"],
        )
    )

    matched_cves = {item["cve_id"] for item in assessments}
    matched_assets = {item["asset_id"] for item in assessments}

    return {
        "assessments": assessments,
        "finding_cves_without_rule_match": sorted(
            set(findings_by_cve) - matched_cves
        ),
        "asset_ids_without_rule_match": sorted(
            asset["asset_id"]
            for asset in inventory["assets"]
            if asset["asset_id"] not in matched_assets
        ),
        "rules_without_findings": sorted(rules_without_findings),
        "rules_without_components": sorted(rules_without_components),
    }


def load_json(path):
    raw = Path(path).read_bytes()
    if len(raw) > 30 * 1024 * 1024:
        raise ValueError("Input exceeds size limit.")
    return json.loads(raw.decode("utf-8-sig"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings", required=True)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--rules", required=True)
    args = parser.parse_args()

    try:
        dataset = load_json(args.findings)
        inventory = load_json(args.inventory)
        rules = load_json(args.rules)

        if not isinstance(dataset, dict):
            raise ValueError("Normalized dataset must be an object.")

        findings = dataset.get("findings")
        if not isinstance(findings, list):
            raise ValueError("Normalized findings are missing.")

        if fingerprint(findings) != dataset.get("findings_sha256"):
            raise ValueError("Normalized findings fingerprint mismatch.")

        result = assess_findings(findings, inventory, rules)

        output = {
            "schema_version": "1.0",
            "synthetic": True,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "input_findings_sha256": dataset["findings_sha256"],
            "inventory_sha256": fingerprint(inventory),
            "review_rules_sha256": fingerprint(rules),
            "source_provenance": dataset.get("sources"),
            **result,
        }

        run_id = (
            datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            + "-"
            + uuid4().hex[:8]
        )

        folder = PROJECT_ROOT / "data/processed" / run_id
        folder.mkdir(parents=True, exist_ok=False)
        path = folder / "asset-assessments.json"
        path.write_text(
            json.dumps(output, indent=2, allow_nan=False),
            encoding="utf-8",
        )

        print(
            "PASS: created",
            len(result["assessments"]),
            "candidate asset assessments",
        )
        print(
            "Assets without a review-rule match:",
            len(result["asset_ids_without_rule_match"]),
        )
        print(
            "Findings without a review-rule match:",
            len(result["finding_cves_without_rule_match"]),
        )
        print("All candidate assessments require analyst review.")
        print(f"Saved to: {path}")

    except (OSError, ValueError, KeyError, TypeError) as error:
        print(
            f"Assessment failed: {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())