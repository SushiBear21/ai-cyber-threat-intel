import unittest

from app.render_report import render_report, safe


class ReportTests(unittest.TestCase):
    def test_html_and_markdown_are_escaped(self):
        result = safe("<script>alert(1)</script>\n# Heading")
        self.assertNotIn("<script>", result)
        self.assertNotIn("\n", result)
        self.assertIn("&lt;script&gt;", result)
        self.assertIn("\\# Heading", result)

    def test_mismatched_analysis_is_rejected(self):
        from app.normalize import fingerprint

        candidates = [{"candidate_id": "synthetic"}]
        priorities = {
            "synthetic": True,
            "candidates": candidates,
            "candidates_sha256": fingerprint(candidates),
        }
        analysis = {
            "synthetic": True,
            "input_candidates_sha256": "wrong",
        }

        with self.assertRaisesRegex(ValueError, "different candidates"):
            render_report(priorities, analysis)


if __name__ == "__main__":
    unittest.main()