import unittest
from pathlib import Path

from nucleotide.fingerprint import extract_fingerprints
from nucleotide.parse import parse_template

FIXTURES = Path(__file__).parent / "fixtures"


class TestFingerprint(unittest.TestCase):
    def test_http_template_yields_ua_and_shape(self):
        doc = parse_template(FIXTURES / "wp-foo.yaml")
        fp = extract_fingerprints(doc)
        self.assertIn("FooScanner/1.0", fp["user_agents"])
        self.assertIn("user-agent", fp["header_names"])
        self.assertIn("x-foo-probe", fp["header_names"])
        self.assertTrue(fp["header_signature"].startswith("sha256:"))
        self.assertTrue(fp["header_order_signature"].startswith("sha256:"))
        self.assertTrue(fp["request_shape"].startswith("sha256:"))
        self.assertEqual(fp["http_methods"], ["GET"])
        # Order-preserving capture keeps the YAML declaration order.
        self.assertEqual(
            fp["header_order"],
            [["User-Agent", "FooScanner/1.0"], ["X-Foo-Probe", "alpha"]],
        )

    def test_header_order_preserved_for_synthetic_doc(self):
        doc = {
            "id": "x",
            "info": {"name": "x"},
            "http": [
                {
                    "method": "GET",
                    "path": ["/x"],
                    "headers": {
                        "User-Agent": "Probe/1",
                        "X-Trace": "abc",
                        "X-Then": "def",
                    },
                }
            ],
        }
        fp = extract_fingerprints(doc)
        self.assertEqual(
            fp["header_order"],
            [
                ["User-Agent", "Probe/1"],
                ["X-Trace", "abc"],
                ["X-Then", "def"],
            ],
        )

    def test_cookies_extracted_from_cookie_header(self):
        doc = {
            "id": "x",
            "info": {"name": "x"},
            "http": [
                {
                    "method": "GET",
                    "path": ["/x"],
                    "headers": {"Cookie": "sid=abc; tracker=xyz"},
                }
            ],
        }
        fp = extract_fingerprints(doc)
        self.assertEqual(fp["cookie_names"], ["sid", "tracker"])
        self.assertEqual(fp["cookies"], [["sid", "abc"], ["tracker", "xyz"]])
        self.assertTrue(fp["cookie_signature"].startswith("sha256:"))

    def test_cookies_extracted_from_raw_request(self):
        doc = {
            "id": "x",
            "info": {"name": "x"},
            "http": [
                {
                    "raw": [
                        "GET /x HTTP/1.1\n"
                        "Host: t\n"
                        "Cookie: a=1; b=2\n"
                        "\n"
                    ]
                }
            ],
        }
        fp = extract_fingerprints(doc)
        self.assertEqual(fp["cookie_names"], ["a", "b"])

    def test_oast_injection_detected_in_body_and_header(self):
        doc = {
            "id": "x",
            "info": {"name": "x"},
            "http": [
                {
                    "method": "POST",
                    "path": ["/x"],
                    "headers": {"X-Callback": "http://{{interactsh-url}}/cb"},
                    "body": '{"u":"http://{{interactsh-url}}/probe"}',
                }
            ],
        }
        fp = extract_fingerprints(doc)
        self.assertGreaterEqual(fp["oast_injection_count"], 2)
        self.assertIn("http[0].body", fp["oast_locations"])
        self.assertIn("http[0].header:X-Callback", fp["oast_locations"])
        self.assertEqual(fp["oast_placeholders"], ["{{interactsh-url}}"])

    def test_raw_template_yields_raw_signature(self):
        doc = parse_template(FIXTURES / "api-quux.yaml")
        fp = extract_fingerprints(doc)
        self.assertIn("raw_request_signatures", fp)
        self.assertEqual(len(fp["raw_request_signatures"]), 1)

    def test_network_template_yields_byte_signatures(self):
        doc = parse_template(FIXTURES / "network-redis.yaml")
        fp = extract_fingerprints(doc)
        self.assertIn("network_byte_signatures", fp)
        sigs = fp["network_byte_signatures"]
        hex_sig = next(s for s in sigs if s.startswith("hex:"))
        self.assertNotIn(" ", hex_sig)
        self.assertEqual(hex_sig, "hex:2a310d0a24340d0a494e464f0d0a")

    def test_no_ja3_without_full_tls_config(self):
        doc = parse_template(FIXTURES / "wp-foo.yaml")
        fp = extract_fingerprints(doc)
        self.assertNotIn("ja3", fp)
        self.assertNotIn("ja4", fp)

    def test_ja3_when_tls_config_complete(self):
        doc = {
            "id": "tls-probe",
            "info": {"name": "x"},
            "tls-config": {
                "version": 771,
                "ciphers": [49195, 49199, 49196],
                "extensions": [0, 23, 65281, 10, 11],
                "curves": [29, 23, 24],
                "ec_point_formats": [0],
            },
        }
        fp = extract_fingerprints(doc)
        self.assertIn("ja3", fp)
        self.assertEqual(len(fp["ja3"]), 32)


if __name__ == "__main__":
    unittest.main()
