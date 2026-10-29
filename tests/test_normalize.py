import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from app.normalize import (
    fingerprint,
    load_snapshot,
    normalize_findings,
)


CVE = "CVE-2021-44228"


def kev_fixture():
    return {
        "catalogVersion": "test-version",
        "dateReleased": "2026-10-28T19:00:00Z",
        "count": 1,
        "vulnerabilities": [{
            "cveID": CVE,
            "vendorProject": " Synthetic Vendor ",
            "product": "Synthetic Product",
            "vulnerabilityName": "Synthetic vulnerability",
            "shortDescription": "Synthetic description.",
            "requiredAction": "Review vendor guidance.",
            "dateAdded": "2026-10-28",
            "dueDate": "2026-11-18",
        }],
    }


def epss_fixture():
    return {
        "status": "OK",
        "data": [{
            "cve": CVE,
            "epss": "0.75",
            "percentile": "0.99",
            "date": "2026-10-28",
        }],
    }


class NormalizationTests(unittest.TestCase):
    def test_sources_join_by_cve(self):
        findings = normalize_findings(
            kev_fixture(), epss_fixture(), [CVE]
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vendor"], "Synthetic Vendor")
        self.assertEqual(findings[0]["epss"]["probability"], 0.75)
        self.assertEqual(findings[0]["epss"]["status"], "available")
        self.assertEqual(
            findings[0]["asset_applicability"], "not_assessed"
        )

    def test_requested_missing_is_explicit(self):
        findings = normalize_findings(
            kev_fixture(), {"status": "OK", "data": []}, [CVE]
        )

        self.assertEqual(
            findings[0]["epss"]["status"], "requested_missing"
        )
        self.assertIsNone(findings[0]["epss"]["probability"])

    def test_not_requested_is_distinct_from_missing(self):
        findings = normalize_findings(
            kev_fixture(),
            {"status": "OK", "data": []},
            ["CVE-2017-0144"],
        )

        self.assertEqual(
            findings[0]["epss"]["status"], "not_requested"
        )

    def test_duplicate_kev_record_is_rejected(self):
        kev = kev_fixture()
        kev["vulnerabilities"].append(
            copy.deepcopy(kev["vulnerabilities"][0])
        )
        kev["count"] = 2

        with self.assertRaisesRegex(ValueError, "Duplicate CVE"):
            normalize_findings(kev, epss_fixture(), [CVE])

    def test_input_order_does_not_change_findings(self):
        kev = kev_fixture()
        other = copy.deepcopy(kev["vulnerabilities"][0])
        other["cveID"] = "CVE-2017-0144"
        kev["vulnerabilities"].append(other)
        kev["count"] = 2

        first = normalize_findings(kev, epss_fixture(), [CVE])
        kev["vulnerabilities"].reverse()
        second = normalize_findings(kev, epss_fixture(), [CVE])

        self.assertEqual(first, second)
        self.assertEqual(fingerprint(first), fingerprint(second))

    def test_score_change_changes_fingerprint(self):
        epss = epss_fixture()
        first = normalize_findings(kev_fixture(), epss, [CVE])

        epss["data"][0]["epss"] = "0.80"
        second = normalize_findings(kev_fixture(), epss, [CVE])

        self.assertNotEqual(fingerprint(first), fingerprint(second))

    def test_tampered_saved_snapshot_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            original = b'{"original": true}'

            manifest = {
                "raw_file": "response.json",
                "sha256": hashlib.sha256(original).hexdigest(),
                "bytes": len(original),
                "source": "Synthetic source",
                "requested_url": "https://example.invalid",
                "collected_at": "2026-10-28T00:00:00Z",
            }

            (folder / "manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            (folder / "response.json").write_bytes(
                b'{"modified": true}'
            )

            with self.assertRaisesRegex(ValueError, "hash"):
                load_snapshot(folder, "response.json")


if __name__ == "__main__":
    unittest.main()