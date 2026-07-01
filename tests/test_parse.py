import unittest
from pathlib import Path

from nucleotide.parse import (
    extract_literal_chunks,
    extract_payloads,
    iter_template_files,
    materialize_paths,
    normalize_paths,
    parse_template,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestParse(unittest.TestCase):
    def test_iter_finds_yaml_files(self):
        files = sorted(p.name for p in iter_template_files(FIXTURES))
        self.assertIn("akismet.yaml", files)
        self.assertIn("contact-form-7.yaml", files)
        self.assertIn("CVE-2021-44228.yaml", files)
        self.assertIn("redis-detect.yaml", files)

    def test_parse_template_returns_dict(self):
        doc = parse_template(FIXTURES / "akismet.yaml")
        self.assertIsNotNone(doc)
        self.assertEqual(doc["id"], "wordpress-akismet")

    def test_normalize_paths_path_block(self):
        doc = parse_template(FIXTURES / "akismet.yaml")
        paths = normalize_paths(doc)
        self.assertEqual(
            paths, ["{{BaseURL}}/wp-content/plugins/akismet/readme.txt"]
        )

    def test_normalize_paths_raw_block(self):
        doc = parse_template(FIXTURES / "CVE-2021-44228.yaml")
        paths = normalize_paths(doc)
        # The Log4Shell template has two raw HTTP requests: a Log4j payload in
        # the URI and a plain `GET /`.
        self.assertEqual(len(paths), 2)
        self.assertTrue(paths[0].startswith("/?x=${jndi:ldap://"))
        self.assertEqual(paths[1], "/")

    def test_extract_literal_chunks_strips_placeholders(self):
        chunks = extract_literal_chunks("{{BaseURL}}/wp-content/plugins/akismet/readme.txt")
        self.assertEqual(chunks, ["/wp-content/plugins/akismet/readme.txt"])
        chunks = extract_literal_chunks("/a/{{x}}/b/{{y}}")
        self.assertEqual(chunks, ["/a/", "/b/"])

    def test_extract_payloads_reads_inline_lists(self):
        doc = parse_template(FIXTURES / "laravel-env.yaml")
        payloads = extract_payloads(doc)
        self.assertIn("paths", payloads)
        self.assertIn("/.env", payloads["paths"])
        self.assertIn("/.env.production", payloads["paths"])

    def test_extract_payloads_skips_external_file_references(self):
        # Nuclei allows `payloads: {X: helpers/foo.txt}`. Without the helper
        # file we can't materialize; the extractor must not crash and must
        # return an empty result for such payloads.
        doc = {
            "id": "x",
            "info": {"name": "x"},
            "http": [
                {
                    "path": ["/x"],
                    "payloads": {"external": "helpers/tokens.txt"},
                }
            ],
        }
        self.assertEqual(extract_payloads(doc), {})

    def test_materialize_paths_substitutes_placeholder(self):
        paths = ["{{BaseURL}}{{P}}"]
        payloads = {"P": ["/.env", "/.env.bak"]}
        out = materialize_paths(paths, payloads)
        self.assertIn("{{BaseURL}}/.env", out)
        self.assertIn("{{BaseURL}}/.env.bak", out)
        # Original path is preserved too.
        self.assertIn("{{BaseURL}}{{P}}", out)

    def test_materialize_paths_bounds_expansion(self):
        # A cap prevents runaway materialization when a payload list is huge.
        paths = ["{{BaseURL}}{{P}}"]
        payloads = {"P": [f"/x{i}" for i in range(200)]}
        out = materialize_paths(paths, payloads, cap=5)
        # +1 for the original, +cap materialized entries at most.
        self.assertLessEqual(len(out), 6)


if __name__ == "__main__":
    unittest.main()
