import unittest
from pathlib import Path

from nucleotide.parse import (
    extract_literal_chunks,
    iter_template_files,
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


if __name__ == "__main__":
    unittest.main()
