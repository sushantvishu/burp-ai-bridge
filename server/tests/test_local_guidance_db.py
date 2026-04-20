import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from server import local_guidance_db

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "guidance_db" / "guidance_matrix.json"


class LocalGuidanceDbTests(unittest.TestCase):
    def test_query_guidance_packs_returns_structured_hits(self):
        result = local_guidance_db.query_guidance_packs(["idor", "xss"], top_k=5)

        self.assertTrue(result["hits"])
        first = result["hits"][0]
        self.assertIn("style", first)
        self.assertIn("matched_classes", first)
        self.assertIn("guidance", first)
        self.assertTrue(result["context"])
        self.assertTrue(any("github.com" in link or "portswigger.net" in link for link in result["reference_links"]))

    def test_guidance_matrix_covers_major_web_and_api_classes(self):
        matrix = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        for item in matrix:
            with self.subTest(vuln_class=item["vuln_class"]):
                result = local_guidance_db.query_guidance_packs([item["vuln_class"]], top_k=8)
                styles = {hit["style"] for hit in result["hits"]}
                rendered = result["context"].lower()
                refs = " ".join(result["reference_links"]).lower()
                for required_style in item["required_styles"]:
                    self.assertIn(required_style, styles)
                for term in item["required_terms"]:
                    normalized = term.lower()
                    self.assertTrue(normalized in rendered or normalized in refs)

    def test_guidance_merge_policy_and_feedback_score_fields_are_present(self):
        result = local_guidance_db.query_guidance_packs(["idor"], top_k=4)

        self.assertEqual(result["merge_policy"][0], "program_policy_gates")
        self.assertIn("guidance_db", result["merge_policy"])
        self.assertIn("feedback_score", result["hits"][0])
        self.assertIn("influence_reason", result["hits"][0])


if __name__ == "__main__":
    unittest.main()
