import json
import unittest
from pathlib import Path

from nucleotide.build import build_lookup
from nucleotide.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


class TestBuild(unittest.TestCase):
    def test_end_to_end_against_real_templates(self):
        result = build_lookup(FIXTURES, source_url="fixtures")
        md = result["metadata"]
        # Four vendored real templates: two WP plugins + Log4Shell + redis-detect.
        self.assertEqual(md["template_count"], 4)
        self.assertEqual(md["http_template_count"], 3)
        self.assertEqual(md["resolved_snippets"], 3)
        self.assertEqual(md["unresolved_count"], 0)
        self.assertEqual(md["no_url_template_count"], 1)

        ids = {t["id"] for t in result["templates"].values()}
        self.assertEqual(
            ids,
            {
                "wordpress-akismet",
                "wordpress-contact-form-7",
                "CVE-2021-44228",
                "redis-detect",
            },
        )

        # redis-detect is tcp-only: no URL, but yields a network byte signature.
        redis = next(t for t in result["templates"].values() if t["id"] == "redis-detect")
        self.assertIsNone(redis["url_snippet"])
        self.assertIn("network_byte_signatures", redis["fingerprints"])

        # All resolved snippets respect min_snippet_len (4).
        index = result["snippet_index"]
        for snip in index:
            self.assertGreaterEqual(len(snip), 4)

        # The two WP plugin templates share the `/wp-content/plugins/` prefix
        # but get distinct unique snippets that don't collide.
        akismet = next(t for t in result["templates"].values() if t["id"] == "wordpress-akismet")
        cf7 = next(t for t in result["templates"].values() if t["id"] == "wordpress-contact-form-7")
        self.assertIn(akismet["url_snippet"], akismet["paths"][0])
        self.assertNotIn(akismet["url_snippet"], cf7["paths"][0])
        self.assertIn(cf7["url_snippet"], cf7["paths"][0])
        self.assertNotIn(cf7["url_snippet"], akismet["paths"][0])

    def test_log4shell_template_captures_payload_signals(self):
        result = build_lookup(FIXTURES, source_url="fixtures")
        log4j = next(
            t for t in result["templates"].values() if t["id"] == "CVE-2021-44228"
        )
        fp = log4j["fingerprints"]
        # Two raw HTTP requests in the template.
        self.assertEqual(len(fp["raw_request_signatures"]), 2)
        # Many ordered custom headers: cookie + UA + assorted forwarding headers.
        names = fp["header_order_names"]
        for required in ("cookie", "user-agent", "referer", "x-forwarded-for"):
            self.assertIn(required, names)
        # OAST callbacks captured across the header set.
        self.assertGreaterEqual(fp["oast_injection_count"], 17)
        self.assertEqual(fp["oast_placeholders"], ["{{interactsh-url}}"])
        # Cookie header was parsed back out of the raw request.
        self.assertEqual(len(fp["cookie_names"]), 1)

    def test_signatures_emitted_for_real_templates(self):
        result = build_lookup(FIXTURES, source_url="fixtures")
        sigs = result["signatures"]
        self.assertIn("yara", sigs)
        self.assertIn("snort", sigs)

        # Log4Shell template yields a YARA rule and Snort rules.
        yara = sigs["yara"].get("CVE-2021-44228")
        self.assertIsNotNone(yara)
        self.assertIn("rule nuclei_CVE_2021_44228", yara)
        self.assertIn('nuclei_id = "CVE-2021-44228"', yara)
        self.assertIn('severity = "critical"', yara)

        snort_rules = sigs["snort"].get("CVE-2021-44228") or []
        self.assertTrue(snort_rules)
        joined = "\n".join(snort_rules)
        self.assertIn("alert http ", joined)
        self.assertIn("http_uri", joined)
        # The WP-plugin templates have a path snippet but no UA / cookies / OAST,
        # so they should still each produce at least one URI-anchored Snort rule.
        for tid in ("wordpress-akismet", "wordpress-contact-form-7"):
            wp_snort = sigs["snort"].get(tid) or []
            self.assertTrue(
                any("http_uri" in r for r in wp_snort),
                f"{tid} should produce a Snort URI rule",
            )

    def test_cli_build_and_lookup(self):
        out = FIXTURES.parent / "tmp-lookup.json"
        try:
            rc = main(["build", "--templates-dir", str(FIXTURES), "--out", str(out)])
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text())
            self.assertEqual(data["metadata"]["template_count"], 4)
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
