import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from server.core import burp_action_service
from server.core import impact_service
from server.core import validation_service


FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "evaluations"


class EvaluationFixtureTests(unittest.TestCase):
    def test_validation_and_impact_outputs_match_reference_fixtures(self):
        for fixture_path in sorted(FIXTURE_DIR.glob("*.json")):
            with self.subTest(fixture=fixture_path.name):
                fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
                payload = fixture["payload"]
                advisory = fixture["advisory"]
                run = fixture["run"]
                expected = fixture["expected"]

                validation = validation_service.validate_hypothesis(payload, advisory=advisory, run=run)
                impact = impact_service.rank_impact_paths(payload, advisory=advisory, run=run)
                with patch.object(burp_action_service, "rank_impact_paths", return_value=impact):
                    burp = burp_action_service.next_burp_action(payload, advisory=advisory)

                self.assertEqual(validation["validation_status"], expected["validation_status"])
                self.assertEqual(bool(impact["reportable"]), expected["reportable"])
                self.assertEqual(impact["reportability"], expected["reportability"])
                self.assertEqual(impact["business_impact_class"], expected["business_impact_class"])
                self.assertEqual(bool(burp["safe_to_expand"]), expected["safe_to_expand"])
                if "policy_gate_applies" in expected:
                    self.assertEqual(bool((impact.get("policy_gate") or {}).get("applies")), expected["policy_gate_applies"])
                if "policy_gate_allowed" in expected:
                    self.assertEqual(bool((impact.get("policy_gate") or {}).get("allowed")), expected["policy_gate_allowed"])


if __name__ == "__main__":
    unittest.main()
