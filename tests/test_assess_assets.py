import copy
import unittest

from app.assess_assets import assess_findings


CVE = "CVE-2021-44228"


def inventory_fixture():
    return {
        "synthetic": True,
        "assets": [{
            "asset_id": "SYN-001",
            "name": "Synthetic Portal",
            "owner": "Synthetic Operations",
            "business_criticality": "high",
            "internet_exposed": True,
            "components": [{
                "component_id": "CMP-001",
                "component_key": "demo_component",
                "vendor": "Synthetic Vendor",
                "product": "Synthetic Product",
                "version": "unknown",
            }],
        }],
    }


def rules_fixture():
    return {
        "synthetic": True,
        "rules": [{
            "rule_id": "RULE-001",
            "cve_id": CVE,
            "component_key": "demo_component",
            "basis": "Synthetic exercise rule; verify applicability.",
        }],
    }


class AssetAssessmentTests(unittest.TestCase):
    def test_explicit_rule_creates_review_candidate(self):
        result = assess_findings(
            [{"cve_id": CVE}],
            inventory_fixture(),
            rules_fixture(),
        )

        self.assertEqual(len(result["assessments"]), 1)
        candidate = result["assessments"][0]
        self.assertEqual(candidate["applicability"], "needs_review")
        self.assertEqual(candidate["version_check"], "not_performed")
        self.assertEqual(candidate["patch_status"], "not_assessed")

    def test_product_name_alone_does_not_create_match(self):
        inventory = inventory_fixture()
        inventory["assets"][0]["components"][0][
            "component_key"
        ] = "different_key"

        result = assess_findings(
            [{"cve_id": CVE, "product": "Synthetic Product"}],
            inventory,
            rules_fixture(),
        )

        self.assertEqual(result["assessments"], [])
        self.assertEqual(
            result["asset_ids_without_rule_match"], ["SYN-001"]
        )

    def test_no_rule_does_not_mean_asset_is_safe(self):
        result = assess_findings(
            [{"cve_id": CVE}],
            inventory_fixture(),
            {"synthetic": True, "rules": []},
        )

        self.assertEqual(result["assessments"], [])
        self.assertEqual(
            result["finding_cves_without_rule_match"], [CVE]
        )
        self.assertEqual(
            result["asset_ids_without_rule_match"], ["SYN-001"]
        )

    def test_duplicate_asset_id_is_rejected(self):
        inventory = inventory_fixture()
        inventory["assets"].append(
            copy.deepcopy(inventory["assets"][0])
        )

        with self.assertRaisesRegex(ValueError, "Duplicate asset ID"):
            assess_findings(
                [{"cve_id": CVE}], inventory, rules_fixture()
            )

    def test_unknown_exposure_is_rejected(self):
        inventory = inventory_fixture()
        inventory["assets"][0]["internet_exposed"] = "unknown"

        with self.assertRaisesRegex(ValueError, "Exposure"):
            assess_findings(
                [{"cve_id": CVE}], inventory, rules_fixture()
            )

    def test_rule_without_finding_is_reported(self):
        result = assess_findings(
            [], inventory_fixture(), rules_fixture()
        )

        self.assertEqual(result["assessments"], [])
        self.assertEqual(
            result["rules_without_findings"], ["RULE-001"]
        )

    def test_multiple_assets_can_require_review(self):
        inventory = inventory_fixture()
        second = copy.deepcopy(inventory["assets"][0])
        second["asset_id"] = "SYN-002"
        second["components"][0]["component_id"] = "CMP-002"
        inventory["assets"].append(second)

        result = assess_findings(
            [{"cve_id": CVE}], inventory, rules_fixture()
        )

        self.assertEqual(len(result["assessments"]), 2)

    def test_duplicate_review_rule_is_rejected(self):
        rules = rules_fixture()
        duplicate = copy.deepcopy(rules["rules"][0])
        duplicate["rule_id"] = "RULE-002"
        rules["rules"].append(duplicate)

        with self.assertRaisesRegex(ValueError, "Duplicate CVE/component"):
            assess_findings(
                [{"cve_id": CVE}], inventory_fixture(), rules
            )


if __name__ == "__main__":
    unittest.main()