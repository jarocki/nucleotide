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

    def test_prefers_shortest_anchored(self):
        # Selection prefers the shortest *anchored* unique substring over a
        # shorter mid-token fragment. Both templates differ only by the token
        # after `/zzz/`; the chosen snippet must be uniquely identifying and
        # must sit on a path boundary rather than slicing across one.
        corpus = {
            "a": ["/zzz/aaa-distinctive/end"],
            "b": ["/zzz/bbb-distinctive/end"],
        }
        snippets, _ = compute_unique_snippets(corpus, min_len=3, max_len=40)
        self.assertIn(snippets["a"], "/zzz/aaa-distinctive/end")
        self.assertNotIn(snippets["a"], "/zzz/bbb-distinctive/end")
        # The snippet is anchored: it starts at a boundary and does not begin
        # mid-token (i.e. not a bare 'aa' slice inside 'aaa').
        chunk = "/zzz/aaa-distinctive/end"
        idx = chunk.find(snippets["a"])
        self.assertTrue(idx == 0 or chunk[idx - 1] in "/?=&.:;,%+ ")

    def test_falls_back_to_unanchored_when_no_anchored_unique(self):
        # If no anchored substring is unique, selection still resolves the
        # template on the shortest unique (unanchored) substring rather than
        # dropping it as unresolved.
        corpus = {
            "a": ["/samepath/xQ"],
            "b": ["/samepath/xR"],
        }
        snippets, unresolved = compute_unique_snippets(corpus, min_len=2, max_len=40)
        self.assertEqual(set(snippets), {"a", "b"})
        self.assertEqual(unresolved, [])

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
