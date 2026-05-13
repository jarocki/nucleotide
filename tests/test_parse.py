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
        self.assertIn("wp-foo.yaml", files)
        self.assertIn("api-quux.yaml", files)

    def test_parse_template_returns_dict(self):
        doc = parse_template(FIXTURES / "wp-foo.yaml")
        self.assertIsNotNone(doc)
        self.assertEqual(doc["id"], "wp-foo-plugin")

    def test_normalize_paths_path_block(self):
        doc = parse_template(FIXTURES / "wp-foo.yaml")
        paths = normalize_paths(doc)
        self.assertEqual(paths, ["{{BaseURL}}/wp-content/plugins/foo-bar/readme.txt"])

    def test_normalize_paths_raw_block(self):
        doc = parse_template(FIXTURES / "api-quux.yaml")
        paths = normalize_paths(doc)
        self.assertEqual(paths, ["/api/v3/quux/echo"])

    def test_extract_literal_chunks_strips_placeholders(self):
        chunks = extract_literal_chunks("{{BaseURL}}/wp-content/plugins/foo-bar/readme.txt")
        self.assertEqual(chunks, ["/wp-content/plugins/foo-bar/readme.txt"])
        chunks = extract_literal_chunks("/a/{{x}}/b/{{y}}")
        self.assertEqual(chunks, ["/a/", "/b/"])


if __name__ == "__main__":
    unittest.main()
