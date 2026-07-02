import re
import unittest

from nucleotide.sigma import (
    _sigma_id,
    build_sigma,
    render_sigma,
    render_sigma_by_tier,
    sigma_rules_for,
)


class TestSigmaBasics(unittest.TestCase):
    def test_sigma_id_is_deterministic_and_uuid_shaped(self):
        a = _sigma_id("CVE-2021-44228", "T1")
        b = _sigma_id("CVE-2021-44228", "T1")
        self.assertEqual(a, b)
        # UUID-shaped: 8-4-4-4-12
        self.assertRegex(a, r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        # Same tid different tier -> distinct id.
        self.assertNotEqual(a, _sigma_id("CVE-2021-44228", "T5"))

    def test_t1_rule_contains_uri_and_ua_selection(self):
        t = {
            "severity": "critical",
            "name": "Demo",
            "chunks": ["/wp-content/plugins/akismet/readme.txt"],
            "fingerprints": {
                "user_agents": ["DemoScanner/1.0"],
            },
        }
        rules = sigma_rules_for("demo", t)
        by_tier = {r["tier"]: r["rule"] for r in rules}
        self.assertIn("T1", by_tier)
        t1 = by_tier["T1"]
        self.assertIn("logsource:", t1)
        self.assertIn("category: webserver", t1)
        self.assertIn("cs-uri-stem|contains", t1)
        self.assertIn("/wp-content/plugins/akismet/readme.txt", t1)
        self.assertIn("cs(User-Agent)|contains", t1)
        self.assertIn("DemoScanner/1.0", t1)
        self.assertIn("level: critical", t1)
        self.assertIn("nucleotide.tier.t1", t1)

    def test_t5_rule_uses_proxy_logsource_and_response_body(self):
        t = {
            "severity": "info",
            "chunks": [],
            "fingerprints": {
                "response_words": ["x-jenkins:", "Jenkins"],
                "response_word_sites": [
                    {"location": "http[0]", "part": "header", "word": "x-jenkins:"},
                    {"location": "http[0]", "part": "body", "word": "Jenkins"},
                ],
            },
        }
        rules = sigma_rules_for("jenkins-detect", t)
        by_tier = {r["tier"]: r["rule"] for r in rules}
        self.assertIn("T5", by_tier)
        t5 = by_tier["T5"]
        self.assertIn("category: proxy", t5)
        self.assertIn("sc-response-body|contains", t5)
        self.assertIn("x-jenkins:", t5)
        self.assertIn("level: informational", t5)

    def test_no_rule_when_no_signal(self):
        self.assertEqual(sigma_rules_for("empty", {"fingerprints": {}}), [])

    def test_dns_response_words_stay_yara_only(self):
        # DNS-side response words don't translate to a webserver access log,
        # so Sigma should not emit a T5 rule for a DNS-only template.
        t = {
            "fingerprints": {
                "response_words": ["NXDOMAIN"],
                "response_word_sites": [
                    {"location": "dns[0]", "part": "body", "word": "NXDOMAIN"}
                ],
            },
        }
        self.assertEqual(sigma_rules_for("dns-only", t), [])


class TestBuildAndRender(unittest.TestCase):
    def _bundle(self):
        lookup = {
            "templates": {
                "a": {
                    "severity": "medium",
                    "chunks": ["/aaaaa/dist-path"],
                    "fingerprints": {},
                },
                "b": {
                    "severity": "info",
                    "chunks": [],
                    "fingerprints": {
                        "response_words": ["distinctive_response"],
                        "response_word_sites": [
                            {"location": "http[0]", "part": "body", "word": "distinctive_response"}
                        ],
                    },
                },
            }
        }
        sigs = {"sigma": build_sigma(lookup)}
        return sigs

    def test_build_sigma_partitions_templates(self):
        sigs = self._bundle()
        self.assertIn("a", sigs["sigma"])
        self.assertIn("b", sigs["sigma"])
        # Template `a` has a request-side signal only -> T1.
        tiers_a = {r["tier"] for r in sigs["sigma"]["a"]}
        self.assertEqual(tiers_a, {"T1"})
        # Template `b` has a response-side signal only -> T5.
        tiers_b = {r["tier"] for r in sigs["sigma"]["b"]}
        self.assertEqual(tiers_b, {"T5"})

    def test_render_sigma_produces_yaml_stream_delimited_by_triple_dashes(self):
        sigs = self._bundle()
        text = render_sigma(sigs)
        self.assertIn("title:", text)
        self.assertIn("---", text)
        # Two rules -> one `---` delimiter (Sigma streams).
        self.assertEqual(text.count("title:"), 2)

    def test_render_sigma_by_tier_returns_t1_and_t5(self):
        sigs = self._bundle()
        per_tier = render_sigma_by_tier(sigs)
        self.assertIn("T1", per_tier)
        self.assertIn("T5", per_tier)
        self.assertIn("category: webserver", per_tier["T1"])
        self.assertIn("category: proxy", per_tier["T5"])
        self.assertNotIn("category: proxy", per_tier["T1"])


if __name__ == "__main__":
    unittest.main()
