import json
import re
import unittest
from pathlib import Path

from nucleotide.build import build_lookup
from nucleotide.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


class TestBuild(unittest.TestCase):
    def test_end_to_end_against_real_templates(self):
        result = build_lookup(FIXTURES, source_url="fixtures")
        md = result["metadata"]
        # 16 vendored real templates: 4 WP plugins, 7 CVEs, exposure config,
        # tech detect, plus tcp/dns/ssl probes with no HTTP surface.
        self.assertEqual(md["template_count"], 16)
        # 4 have no URL surface: redis-detect (tcp), azure-takeover (dns),
        # expired-ssl (ssl), CVE-2014-6271 (path is "{{BaseURL}}{{paths}}"
        # which strips to zero literal chunks).
        self.assertEqual(md["no_url_template_count"], 4)
        # http_template_count == templates that contributed at least one
        # literal URL chunk; the remainder are no_url + unresolved.
        self.assertEqual(
            md["http_template_count"] + md["no_url_template_count"], 16
        )

        ids = {t["id"] for t in result["templates"].values()}
        expected_subset = {
            "wordpress-akismet",
            "wordpress-contact-form-7",
            "wordpress-elementor",
            "wordpress-jetpack",
            "CVE-2021-44228",
            "CVE-2017-5638",
            "CVE-2014-6271",
            "CVE-2022-22965",
            "CVE-2022-1388",
            "CVE-2019-19781",
            "CVE-2021-26084",
            "git-config",
            "jenkins-detect",
            "redis-detect",
            "azure-takeover-detection",
            "expired-ssl",
        }
        self.assertEqual(ids, expected_subset)

        # All resolved snippets respect min_snippet_len (4).
        for snip in result["snippet_index"]:
            self.assertGreaterEqual(len(snip), 4)

        # Four WP plugin templates share /wp-content/plugins/ but get four
        # distinct unique snippets.
        wp_ids = [
            "wordpress-akismet",
            "wordpress-contact-form-7",
            "wordpress-elementor",
            "wordpress-jetpack",
        ]
        wp_snippets = {
            tid: next(
                t["url_snippet"]
                for t in result["templates"].values()
                if t["id"] == tid
            )
            for tid in wp_ids
        }
        self.assertEqual(len(set(wp_snippets.values())), 4)

    def test_log4shell_template_captures_payload_signals(self):
        result = build_lookup(FIXTURES, source_url="fixtures")
        log4j = next(
            t for t in result["templates"].values() if t["id"] == "CVE-2021-44228"
        )
        fp = log4j["fingerprints"]
        self.assertEqual(len(fp["raw_request_signatures"]), 2)
        names = fp["header_order_names"]
        for required in ("cookie", "user-agent", "referer", "x-forwarded-for"):
            self.assertIn(required, names)
        self.assertGreaterEqual(fp["oast_injection_count"], 17)
        self.assertEqual(fp["oast_placeholders"], ["{{interactsh-url}}"])

    def test_struts2_payload_header_becomes_signature(self):
        result = build_lookup(FIXTURES, source_url="fixtures")
        sigs = result["signatures"]
        yara = sigs["yara"].get("CVE-2017-5638")
        self.assertIsNotNone(yara)
        # The OGNL Content-Type payload should be present verbatim in the
        # YARA rule -- generic name + payload value survives the filter.
        self.assertIn("@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS", yara)

    def test_jenkins_detect_emits_response_anchored_snort_rule(self):
        result = build_lookup(FIXTURES, source_url="fixtures")
        sigs = result["signatures"]
        jenkins_snort = sigs["snort"].get("jenkins-detect") or []
        # A response-side anchor (`x-jenkins:`) catches *successful* probes.
        self.assertTrue(
            any(
                "flow:established,to_client" in r and "x-jenkins" in r
                for r in jenkins_snort
            )
        )

    def test_dns_template_emits_yara_only(self):
        result = build_lookup(FIXTURES, source_url="fixtures")
        sigs = result["signatures"]
        # DNS template's `NXDOMAIN` response word produces a YARA rule but
        # not an `alert http` Snort rule.
        self.assertIn("azure-takeover-detection", sigs["yara"])
        self.assertNotIn("azure-takeover-detection", sigs["snort"])

    def test_severity_maps_to_snort_classtype(self):
        result = build_lookup(FIXTURES, source_url="fixtures")
        sigs = result["signatures"]
        # A critical CVE rule should carry the attack classtype...
        log4j_rules = sigs["snort"].get("CVE-2021-44228") or []
        self.assertTrue(log4j_rules)
        self.assertTrue(
            all("classtype:web-application-attack" in r for r in log4j_rules)
        )
        # ...while an `info` severity template stays in the activity bucket.
        akismet_rules = sigs["snort"].get("wordpress-akismet") or []
        self.assertTrue(akismet_rules)
        self.assertTrue(
            all(
                "classtype:web-application-activity" in r for r in akismet_rules
            )
        )

    def test_sid_uniqueness_across_full_bundle(self):
        result = build_lookup(FIXTURES, source_url="fixtures")
        sigs = result["signatures"]
        sids: list[int] = []
        for rules in sigs["snort"].values():
            for r in rules:
                m = re.search(r"sid:(\d+);", r)
                if m:
                    sids.append(int(m.group(1)))
        # Every emitted SID is unique across the whole rule bundle.
        self.assertEqual(len(sids), len(set(sids)))

    def test_path_signatures_use_longest_chunk_not_short_snippet(self):
        result = build_lookup(FIXTURES, source_url="fixtures")
        sigs = result["signatures"]
        # The WP-plugin Snort rule should anchor on the full literal path,
        # not the 4-char unique snippet.
        wp_rule = (sigs["snort"].get("wordpress-akismet") or [""])[0]
        self.assertIn("/wp-content/plugins/akismet/readme.txt", wp_rule)

    def test_cli_build_and_lookup(self):
        out = FIXTURES.parent / "tmp-lookup.json"
        try:
            rc = main(["build", "--templates-dir", str(FIXTURES), "--out", str(out)])
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text())
            self.assertEqual(data["metadata"]["template_count"], 16)
            rc = main(
                [
                    "lookup",
                    str(out),
                    "https://victim.example/wp-content/plugins/akismet/readme.txt",
                ]
            )
            self.assertEqual(rc, 0)
        finally:
            if out.exists():
                out.unlink()

    def test_cli_build_writes_yara_and_snort_files(self):
        tmpdir = FIXTURES.parent / "tmp-signatures"
        tmpdir.mkdir(exist_ok=True)
        out = tmpdir / "lookup.json"
        yara = tmpdir / "rules.yar"
        snort = tmpdir / "rules.rules"
        try:
            rc = main(
                [
                    "build",
                    "--templates-dir",
                    str(FIXTURES),
                    "--out",
                    str(out),
                    "--yara-out",
                    str(yara),
                    "--snort-out",
                    str(snort),
                ]
            )
            self.assertEqual(rc, 0)
            yara_text = yara.read_text()
            self.assertIn("rule nuclei_", yara_text)
            self.assertIn("nuclei_id =", yara_text)
            snort_text = snort.read_text()
            self.assertIn("alert http ", snort_text)
            self.assertIn("sid:", snort_text)
        finally:
            for p in (out, yara, snort):
                if p.exists():
                    p.unlink()
            if tmpdir.exists() and not any(tmpdir.iterdir()):
                tmpdir.rmdir()


if __name__ == "__main__":
    unittest.main()
