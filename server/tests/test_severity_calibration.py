import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from server.core import severity_service


FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "severity_calibration"


class SeverityCalibrationFixtureTests(unittest.TestCase):
    def test_severity_outputs_match_reference_fixtures(self):
        for fixture_path in sorted(FIXTURE_DIR.glob("*.json")):
            with self.subTest(fixture=fixture_path.name):
                fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
                result = severity_service.assess_submission_severity(
                    fixture["payload"],
                    validation=fixture["validation"],
                    impact=fixture["impact"],
                )
                self.assertEqual(result["severity"], fixture["expected"]["severity"])


if __name__ == "__main__":
    unittest.main()
