import unittest

from nucleotide.snippets import compute_unique_snippets


class TestSnippets(unittest.TestCase):
    def test_picks_unique_substring(self):
        corpus = {
            "a": ["/wp-admin/admin-ajax.php?action=foo"],
            "b": ["/wp-admin/admin-ajax.php?action=bar"],
            "c": ["/api/v1/users/baz"],
        }
        snippets, unresolved = compute_unique_snippets(corpus, min_len=4, max_len=40)
        self.assertEqual(set(snippets.keys()), {"a", "b", "c"})
        self.assertEqual(unresolved, [])
        for tid, snip in snippets.items():
            self.assertTrue(any(snip in c for c in corpus[tid]))
            for other in corpus:
                if other == tid:
                    continue
                self.assertFalse(any(snip in c for c in corpus[other]))

    def test_prefers_shortest(self):
        corpus = {
            "a": ["/zzz/very-distinctive-a-token/end"],
            "b": ["/zzz/very-distinctive-b-token/end"],
        }
        snippets, _ = compute_unique_snippets(corpus, min_len=3, max_len=40)
        # min_len is 3 and a single distinguishing character exists, so picks length 3.
        self.assertEqual(len(snippets["a"]), 3)
        self.assertEqual(len(snippets["b"]), 3)
        self.assertIn(snippets["a"], "/zzz/very-distinctive-a-token/end")
        self.assertNotIn(snippets["a"], "/zzz/very-distinctive-b-token/end")

    def test_collision_unresolved(self):
        corpus = {"a": ["/foo"], "b": ["/foo"]}
        snippets, unresolved = compute_unique_snippets(corpus, min_len=3, max_len=10)
        self.assertEqual(snippets, {})
        self.assertEqual(set(unresolved), {"a", "b"})

    def test_empty_chunks_unresolved(self):
        corpus = {"a": [], "b": ["/unique"]}
        snippets, unresolved = compute_unique_snippets(corpus, min_len=3, max_len=10)
        self.assertIn("b", snippets)
        self.assertIn("a", unresolved)


if __name__ == "__main__":
    unittest.main()
