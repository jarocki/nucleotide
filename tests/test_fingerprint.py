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
        self.assertTrue(fp["request_shape"].startswith("sha256:"))
        self.assertEqual(fp["http_methods"], ["GET"])

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
