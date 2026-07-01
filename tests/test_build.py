import json
import re
import unittest
from pathlib import Path

from nucleotide.build import build_lookup
from nucleotide.cli import main

FIXTURES = Path(__file__).parent / "fixtures"

_EXPECTED_IDS = {
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
    "CVE-2020-14882",
    "CVE-2021-41773",
    "CVE-2018-7600",
    "CVE-2022-26134",
    "CVE-2022-40684",
    "CVE-2023-3519",
    "git-config",
    "jenkins-detect",
    "adminer-panel",
    "laravel-env",
    "production-log",
    "redis-detect",
    "azure-takeover-detection",
    "expired-ssl",
    "generic-linux-lfi",
    "error-based-sql-injection",
    "host-header-injection",
    "xss-fuzz",
    "crlf-injection-generic",
    "xmlrpc-pingback-ssrf",
    "oob-param-based-interaction",
}


class TestBuild(unittest.TestCase):
    def test_end_to_end_against_real_templates(self):
        result = build_lookup(FIXTURES, source_url="fixtures")
        md = result["metadata"]
        # 32 vendored real templates spanning WP plugins, CVEs, exposures,
        # tech detects, generic vulnerability probes, plus tcp/dns/ssl
        # probes with no HTTP surface.
        self.assertEqual(md["template_count"], 32)
        # Templates that contribute zero literal URL bytes:
        #   redis-detect (tcp), azure-takeover-detection (dns),
        #   expired-ssl (ssl), host-header-injection (path is just
        #   `{{BaseURL}}`, no literal chunks).
        self.assertEqual(md["no_url_template_count"], 4)

        ids = {t["id"] for t in result["templates"].values()}
        self.assertEqual(ids, _EXPECTED_IDS)

        # All resolved snippets respect min_snippet_len (4).
        for snip in result["snippet_index"]:
            self.assertGreaterEqual(len(snip), 4)

        # Four WP plugin templates share /wp-content/plugins/ but get four
        # distinct unique snippets.
        wp_snippets = {
            tid: next(
                t["url_snippet"]
                for t in result["templates"].values()
                if t["id"] == tid
            )
            for tid in (
                "wordpress-akismet",
                "wordpress-contact-form-7",
                "wordpress-elementor",
                "wordpress-jetpack",
            )
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
        self.assertIn("@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS", yara)

    def test_jenkins_detect_emits_response_anchored_snort_rule(self):
        result = build_lookup(FIXTURES, source_url="fixtures")
        sigs = result["signatures"]
        jenkins_snort = sigs["snort"].get("jenkins-detect") or []
        self.assertTrue(
            any(
                "flow:established,to_client" in r and "x-jenkins" in r
                for r in jenkins_snort
            )
        )

    def test_dns_template_emits_yara_only(self):
        result = build_lookup(FIXTURES, source_url="fixtures")
        sigs = result["signatures"]
        self.assertIn("azure-takeover-detection", sigs["yara"])
        self.assertNotIn("azure-takeover-detection", sigs["snort"])

    def test_severity_maps_to_snort_classtype(self):
        result = build_lookup(FIXTURES, source_url="fixtures")
        sigs = result["signatures"]
        log4j_rules = sigs["snort"].get("CVE-2021-44228") or []
        self.assertTrue(
            all("classtype:web-application-attack" in r for r in log4j_rules)
        )
        akismet_rules = sigs["snort"].get("wordpress-akismet") or []
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
        self.assertEqual(len(sids), len(set(sids)))

    def test_path_signatures_use_longest_chunk_not_short_snippet(self):
        result = build_lookup(FIXTURES, source_url="fixtures")
        sigs = result["signatures"]
        wp_rule = (sigs["snort"].get("wordpress-akismet") or [""])[0]
        self.assertIn("/wp-content/plugins/akismet/readme.txt", wp_rule)

    def test_payload_block_materializes_into_uri_anchors(self):
        # laravel-env has 22 /.env* payload variants but its raw `path:`
        # field is just {{BaseURL}}{{paths}}. Without materialization it
        # produced zero URL chunks; with it, we get concrete anchors.
        result = build_lookup(FIXTURES, source_url="fixtures")
        laravel = next(
            t for t in result["templates"].values() if t["id"] == "laravel-env"
        )
        self.assertTrue(laravel["chunks"], "laravel-env should have chunks")
        self.assertIn("/.env", laravel["chunks"])
        self.assertGreater(len(laravel["materialized_paths"]), 20)
        self.assertIn("paths", laravel["payload_names"])
        # Snort rules cover the actual .env file names.
        rules = result["signatures"]["snort"].get("laravel-env") or []
        joined = "\n".join(rules)
        self.assertIn("/.env", joined)

    def test_lfi_payloads_survive_materialization_cap(self):
        # generic-linux-lfi ships 30+ path payloads. We cap materialization
        # but should still emit multiple distinct URI anchors.
        result = build_lookup(FIXTURES, source_url="fixtures")
        rules = result["signatures"]["snort"].get("generic-linux-lfi") or []
        # Should get multiple URI-anchored rules from the payload variants.
        uri_rules = [r for r in rules if "http_uri" in r]
        self.assertGreaterEqual(len(uri_rules), 3)
        self.assertTrue(any("etc/passwd" in r for r in uri_rules))

    def test_oast_context_clamps_at_placeholder_boundaries(self):
        # oob-param-based-interaction chains 15+ back-to-back
        # {{interactsh-url}} markers separated by short literals like
        # `/&href=http://`. The before/after context must NOT leak
        # `interactsh-url}}` bytes from a neighbouring placeholder.
        result = build_lookup(FIXTURES, source_url="fixtures")
        oob = next(
            t
            for t in result["templates"].values()
            if t["id"] == "oob-param-based-interaction"
        )
        for inj in oob["fingerprints"]["oast_injections"]:
            self.assertNotIn("interactsh-url", inj["before"])
            self.assertNotIn("interactsh-url", inj["after"])

    def test_cli_build_and_lookup(self):
        out = FIXTURES.parent / "tmp-lookup.json"
        try:
            rc = main(["build", "--templates-dir", str(FIXTURES), "--out", str(out)])
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text())
            self.assertEqual(data["metadata"]["template_count"], 32)
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
