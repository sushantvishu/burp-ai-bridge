import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from server.core import repeater_diff_service


FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "repeater_diffs"


class RepeaterDiffFixtureTests(unittest.TestCase):
    def test_repeater_diff_outputs_match_reference_fixtures(self):
        for fixture_path in sorted(FIXTURE_DIR.glob("*.json")):
            with self.subTest(fixture=fixture_path.name):
                fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
                result = repeater_diff_service.score_repeater_diffs(fixture["payload"], plan=fixture["plan"])
                expected = fixture["expected"]

                self.assertEqual(result["best_item"].get("tab_name"), expected["best_tab"])
                self.assertGreaterEqual(float(result["best_item"].get("score", 0.0) or 0.0), expected["min_score"])
                self.assertEqual(bool(result["best_item"].get("high_signal")), expected["high_signal"])
                if "status_transition" in expected:
                    self.assertEqual(result["best_item"].get("status_transition"), expected["status_transition"])


if __name__ == "__main__":
    unittest.main()
