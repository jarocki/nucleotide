import re
import unittest

from nucleotide.signatures import (
    _snort_escape,
    _yara_escape,
    _yara_name,
    build_signatures,
    render_snort,
    render_yara,
    snort_rules_for,
    yara_rule_for,
)


class TestYaraEscaping(unittest.TestCase):
    def test_yara_name_sanitizes_dashes_and_dots(self):
        self.assertEqual(_yara_name("wp-foo-plugin"), "nuclei_wp_foo_plugin")
        self.assertEqual(_yara_name("api.v3.quux"), "nuclei_api_v3_quux")

    def test_yara_escape_handles_quotes_backslashes_and_newlines(self):
        self.assertEqual(_yara_escape('a"b\\c\n'), 'a\\"b\\\\c\\n')

    def test_yara_escape_hex_encodes_high_bytes(self):
        self.assertIn("\\xe2", _yara_escape("—"))


class TestYaraRuleFor(unittest.TestCase):
    def test_rule_includes_path_ua_and_custom_header(self):
        t = {
            "id": "demo-probe",
            "severity": "high",
            "name": "Demo",
            "url_snippet": "/demo/v3/probe",
            "fingerprints": {
                "user_agents": ["DemoScanner/1.0"],
                "header_order": [
                    ["User-Agent", "DemoScanner/1.0"],
                    ["X-Demo", "alpha"],
                    ["Host", "{{Hostname}}"],
                ],
                "cookie_names": ["sid"],
            },
        }
        rule = yara_rule_for("demo-probe", t)
        self.assertIsNotNone(rule)
        self.assertIn("rule nuclei_demo_probe", rule)
        self.assertIn('nuclei_id = "demo-probe"', rule)
        self.assertIn('severity = "high"', rule)
        self.assertIn("/demo/v3/probe", rule)
        self.assertIn("User-Agent: DemoScanner/1.0", rule)
        self.assertIn("X-Demo: alpha", rule)
        self.assertIn("sid=", rule)
        # Generic headers and placeholder-containing values are excluded.
        self.assertNotIn("Host: {{Hostname}}", rule)

    def test_rule_includes_oast_context_anchors(self):
        t = {
            "url_snippet": "/oast/probe",
            "fingerprints": {
                "oast_injections": [
                    {
                        "location": "http[0].body",
                        "placeholder": "{{interactsh-url}}",
                        "before": '"callback":"http://',
                        "after": '/cb","probe":',
                    }
                ],
            },
        }
        rule = yara_rule_for("oast-demo", t)
        # Quotes inside YARA strings are escaped by `_yara_escape`.
        self.assertIn(r'\"callback\":\"http://', rule)
        self.assertIn(r'/cb\",\"probe\":', rule)

    def test_rule_none_when_no_signal(self):
        self.assertIsNone(yara_rule_for("empty", {"fingerprints": {}}))


class TestSnortEscaping(unittest.TestCase):
    def test_printable_ascii_passes_through(self):
        self.assertEqual(_snort_escape("/api/v1/x"), "/api/v1/x")

    def test_reserved_chars_are_hex_encoded(self):
        out = _snort_escape('a"b;c|d\\e')
        self.assertIn("|22|", out)
        self.assertIn("|3B|", out)
        self.assertIn("|7C|", out)
        self.assertIn("|5C|", out)
        self.assertNotIn('"', out)
        self.assertNotIn(";", out.replace("|", ""))


class TestSnortRulesFor(unittest.TestCase):
    def test_rules_cover_uri_ua_header_cookie(self):
        t = {
            "url_snippet": "/demo/v3/probe",
            "fingerprints": {
                "user_agents": ["DemoScanner/1.0"],
                "header_order": [["X-Demo", "alpha"]],
                "cookie_names": ["sid"],
            },
        }
        rules = snort_rules_for("demo-probe", t)
        joined = "\n".join(rules)
        self.assertTrue(rules)
        self.assertIn("http_uri", joined)
        self.assertIn("http_user_agent", joined)
        self.assertIn("http_header", joined)
        self.assertIn("http_cookie", joined)
        sids = re.findall(r"sid:(\d+)", joined)
        self.assertEqual(len(sids), len(rules))
        self.assertEqual(len(set(sids)), len(rules))

    def test_oast_body_uses_client_body_buffer(self):
        t = {
            "fingerprints": {
                "oast_injections": [
                    {
                        "location": "http[0].body",
                        "placeholder": "{{interactsh-url}}",
                        "before": '"callback":"http://',
                        "after": '/cb","mark":7f4',
                    }
                ]
            }
        }
        rules = snort_rules_for("oast-demo", t)
        self.assertTrue(any("http_client_body" in r for r in rules))

    def test_sid_is_stable_for_same_template(self):
        t = {"url_snippet": "/x/y/z"}
        first = snort_rules_for("foo", t)
        second = snort_rules_for("foo", t)
        self.assertEqual(first, second)

    def test_no_rules_without_signal(self):
        self.assertEqual(snort_rules_for("empty", {"fingerprints": {}}), [])


class TestRenderHelpers(unittest.TestCase):
    def test_build_render_round_trip(self):
        lookup = {
            "templates": {
                "a": {
                    "url_snippet": "/aaaaa/b",
                    "fingerprints": {"user_agents": ["UA/1"]},
                },
                "b": {
                    "url_snippet": "/zzzzz/q",
                    "fingerprints": {"user_agents": ["UA/2"]},
                },
            }
        }
        sigs = build_signatures(lookup)
        self.assertIn("a", sigs["yara"])
        self.assertIn("b", sigs["snort"])
        yara_text = render_yara(sigs)
        self.assertIn("rule nuclei_a", yara_text)
        self.assertIn("rule nuclei_b", yara_text)
        snort_text = render_snort(sigs)
        self.assertEqual(snort_text.count("alert http "), len(sigs["snort"]["a"]) + len(sigs["snort"]["b"]))


if __name__ == "__main__":
    unittest.main()
