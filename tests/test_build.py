import json
import unittest
from pathlib import Path

from nucleotide.build import build_lookup
from nucleotide.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


class TestBuild(unittest.TestCase):
    def test_end_to_end_against_fixtures(self):
        result = build_lookup(FIXTURES, source_url="fixtures")
        md = result["metadata"]
        self.assertEqual(md["template_count"], 5)
        self.assertEqual(md["http_template_count"], 4)
        self.assertEqual(md["resolved_snippets"], 4)
        self.assertEqual(md["unresolved_count"], 0)
        self.assertEqual(md["no_url_template_count"], 1)
        redis = next(t for t in result["templates"].values() if t["id"] == "redis-info-probe")
        self.assertIsNone(redis["url_snippet"])
        self.assertIn("network_byte_signatures", redis["fingerprints"])

        ids = {t["id"] for t in result["templates"].values()}
        self.assertEqual(
            ids,
            {
                "wp-foo-plugin",
                "wp-bar-plugin",
                "api-quux-leak",
                "redis-info-probe",
                "ssrf-oast-probe",
            },
        )

        index = result["snippet_index"]
        for snip in index:
            self.assertGreaterEqual(len(snip), 4)

        wp_foo = next(t for t in result["templates"].values() if t["id"] == "wp-foo-plugin")
        wp_bar = next(t for t in result["templates"].values() if t["id"] == "wp-bar-plugin")
        self.assertIn(wp_foo["url_snippet"], wp_foo["paths"][0])
        self.assertNotIn(wp_foo["url_snippet"], wp_bar["paths"][0])

        quux = next(t for t in result["templates"].values() if t["id"] == "api-quux-leak")
        self.assertIn(quux["url_snippet"], "/api/v3/quux/echo")
        self.assertEqual(index[quux["url_snippet"]], "api-quux-leak")

    def test_oast_template_captures_payload_signals(self):
        result = build_lookup(FIXTURES, source_url="fixtures")
        ssrf = next(
            t for t in result["templates"].values() if t["id"] == "ssrf-oast-probe"
        )
        fp = ssrf["fingerprints"]
        # Order-preserving headers and cookies are pulled from the template.
        self.assertEqual(
            fp["header_order"],
            [
                ["Content-Type", "application/json"],
                ["User-Agent", "NucleotideProbe/1.0"],
                ["X-Trace-Id", "abcdef-12345"],
                ["Cookie", "sid=abc123; tracker=xyz"],
            ],
        )
        self.assertEqual(fp["cookie_names"], ["sid", "tracker"])
        # OAST callback marker landed in the request body and was captured.
        self.assertIn("http[0].body", fp["oast_locations"])
        self.assertEqual(fp["oast_placeholders"], ["{{interactsh-url}}"])
        self.assertGreaterEqual(fp["oast_injection_count"], 1)

    def test_signatures_emitted_for_oast_template(self):
        result = build_lookup(FIXTURES, source_url="fixtures")
        sigs = result["signatures"]
        self.assertIn("yara", sigs)
        self.assertIn("snort", sigs)
        yara_rule = sigs["yara"].get("ssrf-oast-probe")
        self.assertIsNotNone(yara_rule)
        self.assertIn("rule nuclei_ssrf_oast_probe", yara_rule)
        self.assertIn("NucleotideProbe/1.0", yara_rule)
        self.assertIn("X-Trace-Id", yara_rule)
        self.assertIn("sid=", yara_rule)

        snort_rules = sigs["snort"].get("ssrf-oast-probe") or []
        self.assertTrue(snort_rules)
        joined = "\n".join(snort_rules)
        self.assertIn("http_uri", joined)
        self.assertIn("http_user_agent", joined)
        self.assertIn("http_cookie", joined)
        self.assertIn("http_client_body", joined)

    def test_cli_build_and_lookup(self):
        out = FIXTURES.parent / "tmp-lookup.json"
        try:
            rc = main(["build", "--templates-dir", str(FIXTURES), "--out", str(out)])
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text())
            self.assertEqual(data["metadata"]["template_count"], 5)
            rc = main(
                [
                    "lookup",
                    str(out),
                    "https://victim.example/wp-content/plugins/foo-bar/readme.txt",
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
