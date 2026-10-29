import unittest

from app.normalize import fingerprint
from app.prioritize import prioritize


def inputs(exposed=True, criticality="high", epss_status="available"):
    finding = {
        "cve_id": "CVE-2021-44228",
        "kev": {"listed": True},
        "epss": {
            "status": epss_status,
            "probability": 0.9 if epss_status == "available" else None,
        },
    }
    dataset = {
        "findings": [finding],
        "findings_sha256": fingerprint([finding]),
        "sources": {},
    }
    assessments = {
        "synthetic": True,
        "input_findings_sha256": dataset["findings_sha256"],
        "finding_cves_without_rule_match": [],
        "asset_ids_without_rule_match": [],
        "assessments": [{
            "cve_id": finding["cve_id"],
            "asset_id": "SYN-001",
            "component_id": "CMP-001",
            "applicability": "needs_review",
            "business_criticality": criticality,
            "internet_exposed": exposed,
        }],
    }
    return dataset, assessments


class PriorityTests(unittest.TestCase):
    def test_exposed_high_criticality_candidate(self):
        result = prioritize(*inputs())
        row = result["candidates"][0]
        self.assertEqual(row["review_score"], 100)
        self.assertEqual(row["review_band"], "expedited_review")

    def test_internal_medium_candidate(self):
        result = prioritize(*inputs(False, "medium"))
        row = result["candidates"][0]
        self.assertEqual(row["review_score"], 70)
        self.assertEqual(row["review_band"], "elevated_review")

    def test_missing_epss_remains_explicit(self):
        result = prioritize(*inputs(epss_status="requested_missing"))
        row = result["candidates"][0]
        self.assertEqual(row["review_score"], 90)
        self.assertEqual(row["data_gaps"], ["EPSS: requested_missing"])

    def test_applicability_is_preserved(self):
        row = prioritize(*inputs())["candidates"][0]
        self.assertEqual(
            row["assessment"]["applicability"], "needs_review"
        )

    def test_wrong_findings_snapshot_is_rejected(self):
        dataset, assessments = inputs()
        assessments["input_findings_sha256"] = "wrong"
        with self.assertRaisesRegex(ValueError, "different findings"):
            prioritize(dataset, assessments)


if __name__ == "__main__":
    unittest.main()