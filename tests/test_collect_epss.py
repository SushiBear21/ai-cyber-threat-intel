import copy
import unittest

from app.collect_epss import validate_response


CVE = "CVE-2021-44228"
OTHER_CVE = "CVE-2017-0144"


def valid_response():
    return {
        "status": "OK",
        "data": [{
            "cve": CVE,
            "epss": "0.75",
            "percentile": "0.99",
            "date": "2026-10-28",
        }],
    }


class EpssValidationTests(unittest.TestCase):
    def test_valid_response_is_accepted(self):
        self.assertEqual(
            validate_response(valid_response(), [CVE]),
            [],
        )

    def test_missing_score_is_reported(self):
        missing = validate_response(
            valid_response(),
            [CVE, OTHER_CVE],
        )

        self.assertEqual(missing, [OTHER_CVE])

    def test_zero_score_is_valid_and_not_missing(self):
        payload = valid_response()
        payload["data"][0]["epss"] = "0"

        self.assertEqual(validate_response(payload, [CVE]), [])

    def test_out_of_range_scores_are_rejected(self):
        for field in ("epss", "percentile"):
            for value in ("-0.1", "1.1"):
                with self.subTest(field=field, value=value):
                    payload = valid_response()
                    payload["data"][0][field] = value

                    with self.assertRaises(ValueError):
                        validate_response(payload, [CVE])

    def test_nonfinite_scores_are_rejected(self):
        for value in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(value=value):
                payload = valid_response()
                payload["data"][0]["epss"] = value

                with self.assertRaises(ValueError):
                    validate_response(payload, [CVE])

    def test_unexpected_cve_is_rejected(self):
        payload = valid_response()
        payload["data"][0]["cve"] = OTHER_CVE

        with self.assertRaisesRegex(ValueError, "Unexpected CVE"):
            validate_response(payload, [CVE])

    def test_duplicate_cve_is_rejected(self):
        payload = valid_response()
        payload["data"].append(copy.deepcopy(payload["data"][0]))

        with self.assertRaisesRegex(ValueError, "Duplicate CVE"):
            validate_response(payload, [CVE])

    def test_invalid_score_date_is_rejected(self):
        payload = valid_response()
        payload["data"][0]["date"] = "2026-02-30"

        with self.assertRaises(ValueError):
            validate_response(payload, [CVE])

    def test_source_error_status_is_rejected(self):
        payload = {"status": "ERROR", "data": []}

        with self.assertRaisesRegex(ValueError, "did not report OK"):
            validate_response(payload, [CVE])


if __name__ == "__main__":
    unittest.main()