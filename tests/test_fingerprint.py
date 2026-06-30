import unittest
from pathlib import Path

from nucleotide.fingerprint import extract_fingerprints
from nucleotide.parse import parse_template

FIXTURES = Path(__file__).parent / "fixtures"


class TestFingerprintRealTemplates(unittest.TestCase):
    """Assertions against the vendored real Nuclei templates in tests/fixtures/."""

    def test_simple_path_template_has_no_custom_headers(self):
        # `akismet.yaml` is a vanilla GET probe with no headers / body / cookies.
        # All it should produce is `http_methods` and a `request_shape` digest.
        doc = parse_template(FIXTURES / "akismet.yaml")
        fp = extract_fingerprints(doc)
        self.assertEqual(fp["http_methods"], ["GET"])
        self.assertTrue(fp["request_shape"].startswith("sha256:"))
        # None of the optional fields fire on a header/body/cookie-less template.
        for absent in (
            "user_agents",
            "header_order",
            "cookies",
            "cookie_names",
            "oast_injections",
            "raw_request_signatures",
            "body_signatures",
            "ja3",
            "ja4",
        ):
            self.assertNotIn(absent, fp, f"unexpected key {absent} on akismet")

    def test_log4shell_template_captures_full_payload(self):
        # CVE-2021-44228 is the gold-standard Log4Shell template: two raw
        # requests, a long ordered list of custom headers, a Cookie header,
        # and {{interactsh-url}} sprinkled into every value.
        doc = parse_template(FIXTURES / "CVE-2021-44228.yaml")
        fp = extract_fingerprints(doc)

        # Two raw blocks → two raw-request signatures.
        self.assertEqual(len(fp["raw_request_signatures"]), 2)
        self.assertEqual(fp["http_methods"], ["GET"])

        # Header order is preserved (and includes the Host headers we parsed
        # back out of each raw request).
        names = fp["header_order_names"]
        for required in (
            "host",
            "user-agent",
            "cookie",
            "accept",
            "accept-encoding",
            "accept-language",
            "x-forwarded-for",
            "referer",
            "origin",
        ):
            self.assertIn(required, names, f"missing header {required}")
        self.assertGreaterEqual(len(fp["header_order"]), 17)
        self.assertTrue(fp["header_order_signature"].startswith("sha256:"))

        # Cookie header survived raw-request parsing.
        self.assertEqual(len(fp["cookie_names"]), 1)
        self.assertIn("{{interactsh-url}}", fp["cookie_names"][0])

        # Every header value carries an {{interactsh-url}} OAST callback, and
        # one shows up in the URI of the first raw request as well.
        self.assertEqual(fp["oast_placeholders"], ["{{interactsh-url}}"])
        self.assertGreaterEqual(fp["oast_injection_count"], 17)
        # OAST sites span both raw requests and include a path injection.
        self.assertTrue(
            any(loc.startswith("http[0].raw[0]") or "raw[0].header" in loc
                for loc in fp["oast_locations"])
        )
        self.assertTrue(
            any("raw[1].header" in loc for loc in fp["oast_locations"])
        )

    def test_tcp_only_template_yields_network_byte_signature(self):
        doc = parse_template(FIXTURES / "redis-detect.yaml")
        fp = extract_fingerprints(doc)
        # The template's tcp input is a plain string (`*1\r\n$4\r\ninfo\r\n`)
        # without a `type: hex` declaration, so we hash it as a string sig.
        self.assertIn("network_byte_signatures", fp)
        self.assertEqual(len(fp["network_byte_signatures"]), 1)
        sig = fp["network_byte_signatures"][0]
        self.assertTrue(sig.startswith("str:"))
        # No HTTP surface → none of the HTTP-side fields fire.
        for absent in ("header_order", "cookies", "raw_request_signatures"):
            self.assertNotIn(absent, fp)

    def test_no_ja3_without_full_tls_config(self):
        doc = parse_template(FIXTURES / "akismet.yaml")
        fp = extract_fingerprints(doc)
        self.assertNotIn("ja3", fp)
        self.assertNotIn("ja4", fp)


class TestFingerprintSyntheticUnits(unittest.TestCase):
    """Direct unit tests on `extract_fingerprints` with minimal Python dict
    inputs. These exercise narrow code paths (a single header dict, a single
    Cookie value, a single OAST marker) without standing up a full Nuclei
    template — the input is a Python-level fixture, not a YAML template
    pretending to be a real Nuclei rule."""

    def test_header_order_preserved(self):
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
