import unittest

from app.analyze import parse_model_json, validate_summary


SUMMARY = (
    "Review the candidate's installed component and patch status. "
    "Asset applicability remains unconfirmed."
)


class AnalysisTests(unittest.TestCase):
    def test_valid_summary_is_accepted(self):
        result = validate_summary(
            {"summary": SUMMARY, "citations": ["KEV", "ASSET"]},
            {"KEV", "ASSET"},
        )
        self.assertEqual(result["citations"], ["ASSET", "KEV"])

    def test_missing_epss_citation_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Citation labels"):
            validate_summary(
                {"summary": SUMMARY, "citations": ["KEV", "ASSET"]},
                {"KEV", "ASSET", "EPSS"},
            )

    def test_model_cannot_add_score_field(self):
        with self.assertRaisesRegex(ValueError, "structure"):
            validate_summary(
                {
                    "summary": SUMMARY,
                    "citations": ["KEV", "ASSET"],
                    "review_score": 0,
                },
                {"KEV", "ASSET"},
            )

    def test_overstated_asset_wording_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "overstates"):
            validate_summary(
                {
                    "summary": SUMMARY + " The affected asset is exposed.",
                    "citations": ["KEV", "ASSET"],
                },
                {"KEV", "ASSET"},
            )

    def test_fenced_json_can_be_parsed(self):
        result = parse_model_json(
            '```json\n{"summary":"example","citations":[]}\n```'
        )
        self.assertEqual(result["summary"], "example")


if __name__ == "__main__":
    unittest.main()