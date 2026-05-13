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
        self.assertEqual(md["template_count"], 4)
        self.assertEqual(md["http_template_count"], 3)
        self.assertEqual(md["resolved_snippets"], 3)
        self.assertEqual(md["unresolved_count"], 0)
        self.assertEqual(md["no_url_template_count"], 1)
        redis = next(t for t in result["templates"].values() if t["id"] == "redis-info-probe")
        self.assertIsNone(redis["url_snippet"])
        self.assertIn("network_byte_signatures", redis["fingerprints"])

        ids = {t["id"] for t in result["templates"].values()}
        self.assertEqual(ids, {"wp-foo-plugin", "wp-bar-plugin", "api-quux-leak", "redis-info-probe"})

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

    def test_cli_build_and_lookup(self):
        out = FIXTURES.parent / "tmp-lookup.json"
        try:
            rc = main(["build", "--templates-dir", str(FIXTURES), "--out", str(out)])
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text())
            self.assertEqual(data["metadata"]["template_count"], 4)
            rc = main(["lookup", str(out), "https://victim.example/wp-content/plugins/foo-bar/readme.txt"])
            self.assertEqual(rc, 0)
        finally:
            if out.exists():
                out.unlink()


if __name__ == "__main__":
    unittest.main()
