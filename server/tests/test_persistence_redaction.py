import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from server.persistence_redaction import redact_persisted_data


class PersistenceRedactionTests(unittest.TestCase):
    def test_redacts_sensitive_headers_tokens_and_query_params(self):
        record = {
            "raw_request": (
                "GET /api/me?token=supersecretvalue HTTP/1.1\r\n"
                "Host: example.com\r\n"
                "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.xyz\r\n"
                "Cookie: sessionid=abcdef1234567890; csrftoken=qwerty1234567890\r\n\r\n"
            ),
            "target_url": "https://example.com/api/me?token=supersecretvalue&view=summary",
            "api_key": "abcdef1234567890",
            "notes": "Authorization: Bearer topsecret1234567890",
            "nested": {
                "session_token": "abcdef1234567890",
                "url": "https://example.com/callback?access_token=secretvalue",
            },
        }

        redacted = redact_persisted_data(record)

        self.assertIn("<redacted>", redacted["raw_request"])
        self.assertIn("token=%3Credacted%3E", redacted["target_url"])
        self.assertEqual(redacted["api_key"], "<redacted>")
        self.assertIn("<redacted>", redacted["notes"])
        self.assertEqual(redacted["nested"]["session_token"], "<redacted>")
        self.assertIn("access_token=%3Credacted%3E", redacted["nested"]["url"])


if __name__ == "__main__":
    unittest.main()
