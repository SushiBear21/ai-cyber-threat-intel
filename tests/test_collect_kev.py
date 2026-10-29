import copy
import unittest

from app.collect_kev import validate_catalog


def valid_catalog():
    return {
        "catalogVersion": "2026.10.28",
        "dateReleased": "2026-10-28T19:00:00Z",
        "count": 1,
        "vulnerabilities": [{
            "cveID": "CVE-2026-12345",
            "vendorProject": "Synthetic Vendor",
            "product": "Synthetic Product",
            "vulnerabilityName": "Synthetic test vulnerability",
            "shortDescription": "Fictional record for validation tests.",
            "requiredAction": "Follow synthetic remediation guidance.",
            "dateAdded": "2026-10-28",
            "dueDate": "2026-11-18",
        }],
    }


class CatalogValidationTests(unittest.TestCase):
    def test_valid_catalog_is_accepted(self):
        self.assertEqual(validate_catalog(valid_catalog()), 1)

    def test_incorrect_count_is_rejected(self):
        catalog = valid_catalog()
        catalog["count"] = 2

        with self.assertRaisesRegex(ValueError, "count"):
            validate_catalog(catalog)

    def test_duplicate_cve_is_rejected(self):
        catalog = valid_catalog()
        catalog["vulnerabilities"].append(
            copy.deepcopy(catalog["vulnerabilities"][0])
        )
        catalog["count"] = 2

        with self.assertRaisesRegex(ValueError, "Duplicate CVE"):
            validate_catalog(catalog)

    def test_invalid_cve_is_rejected(self):
        catalog = valid_catalog()
        catalog["vulnerabilities"][0]["cveID"] = "not-a-cve"

        with self.assertRaisesRegex(ValueError, "Invalid CVE"):
            validate_catalog(catalog)

    def test_missing_required_text_is_rejected(self):
        catalog = valid_catalog()
        catalog["vulnerabilities"][0]["requiredAction"] = " "

        with self.assertRaisesRegex(ValueError, "requiredAction"):
            validate_catalog(catalog)

    def test_invalid_record_date_is_rejected(self):
        catalog = valid_catalog()
        catalog["vulnerabilities"][0]["dateAdded"] = "2026-02-30"

        with self.assertRaises(ValueError):
            validate_catalog(catalog)

    def test_empty_catalog_is_rejected(self):
        catalog = valid_catalog()
        catalog["vulnerabilities"] = []
        catalog["count"] = 0

        with self.assertRaisesRegex(ValueError, "no vulnerability"):
            validate_catalog(catalog)


if __name__ == "__main__":
    unittest.main()