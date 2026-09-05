"""Unit tests for snippet-quality grading.

Every case here is drawn from a real false positive observed when the
full 13,611-template corpus was run against two live capture sets:

  * Honeynet Project T-Pot Log4Shell captures (Dec 2021)
  * galah LLM-honeypot captures (2024)

The red herrings (`e64/`, `//19`, `edis`, `on-3`, `on?@`) are short
substrings that are *unique* across the corpus yet coincidentally appear
in unrelated adversarial traffic. The legitimate short tokens (`saml`,
`mgmt`, `akismet`) are anchored path components that must stay usable.
"""

import unittest

from nucleotide.quality import (
    MEDIUM,
    match_quality,
    STRONG,
    WEAK,
    at_least,
    snippet_quality,
)


class TestAnchoringSeparatesRedHerrings(unittest.TestCase):
    """Anchoring alone must separate coincidental fragments from real tokens."""

    # (snippet, parent_chunk, expected_tier)
    RED_HERRINGS = [
        ("e64/", "/base64/PHNjcmlwdD5hbGVydCg8L3NjcmlwdD4"),  # from 'base64/'
        ("//19", "http://192.168.0.1:22/"),                    # from 'http://192...'
        ("edis", "/redis.conf"),                               # from 'redis'
        ("on-3", "/static/img/icons/favicon-32x32.png"),       # from 'favicon-32'
    ]

    LEGIT_SHORT_TOKENS = [
        ("saml", "/saml/login"),
        ("mgmt", "/mgmt/tm/util/bash"),
        ("akismet", "/wp-content/plugins/akismet/readme.txt"),
    ]

    def test_red_herrings_grade_weak(self):
        for snip, chunk in self.RED_HERRINGS:
            with self.subTest(snippet=snip):
                self.assertEqual(
                    snippet_quality(snip, [chunk]),
                    WEAK,
                    f"{snip!r} sliced from {chunk!r} should be WEAK "
                    f"(coincidental mid-token fragment)",
                )

    def test_legit_short_tokens_grade_medium_or_better(self):
        for snip, chunk in self.LEGIT_SHORT_TOKENS:
            with self.subTest(snippet=snip):
                q = snippet_quality(snip, [chunk])
                self.assertTrue(
                    at_least(q, MEDIUM),
                    f"{snip!r} in {chunk!r} is an anchored path token and "
                    f"should be MEDIUM+, got {q}",
                )


class TestQualityTiers(unittest.TestCase):
    def test_long_anchored_is_strong_or_medium(self):
        # `/autodiscover/` is anchored left (starts at boundary) but continues
        # into another path component (not a boundary on the right), so it's
        # MEDIUM (anchored) but not STRONG (no right boundary). STRONG requires
        # both edges anchored.
        self.assertTrue(
            at_least(
                snippet_quality("/autodiscover/", ["/autodiscover/autodiscover.json"]),
                MEDIUM,
            )
        )

    def test_long_unanchored_earns_medium(self):
        # A 12+ char unanchored slice (truly mid-token, not at boundaries).
        snip = "scriptbodybu"  # pulled from the middle of base64
        chunk = "/mydata/Pyscriptbodybufferdata"
        self.assertEqual(snippet_quality(snip, [chunk]), MEDIUM)

    def test_short_unanchored_is_weak(self):
        self.assertEqual(snippet_quality("bcde", ["/aabcdef/"]), WEAK)

    def test_empty_snippet_is_weak(self):
        self.assertEqual(snippet_quality("", ["/whatever/"]), WEAK)

    def test_anchored_but_short_is_at_least_medium(self):
        # A short anchored token that is not a common word or a bare
        # number beats a coincidental fragment.
        self.assertTrue(at_least(snippet_quality("qzx", ["/qzx/v2/x"]), MEDIUM))

    def test_anchored_common_word_is_weak(self):
        # `Basic` from /WS/Basic/Basic.asmx matched /Basic/Command/Base64/
        # in Log4Shell JNDI payloads; anchoring alone must not lift an
        # ordinary English word to MEDIUM.
        self.assertEqual(snippet_quality("Basic", ["/WS/Basic/Basic.asmx"]), WEAK)
        self.assertEqual(snippet_quality("login", ["/login"]), WEAK)
        self.assertEqual(snippet_quality("/api", ["/api/v2/x"]), WEAK)

    def test_anchored_hex_only_is_weak(self):
        # `6100` from `+OR+6100%3d6100%23` matched inside hex strings.
        self.assertEqual(snippet_quality("6100", ["q=1+OR+6100%3d6100%23"]), WEAK)
        self.assertEqual(snippet_quality("3d50", ["rowCount%3d50%26"]), WEAK)
        self.assertEqual(snippet_quality("ffff", ["/ffff/x"]), WEAK)

    def test_generic_rule_does_not_apply_at_strong_length(self):
        # Length >= 8 and anchored is STRONG regardless of vocabulary.
        self.assertEqual(snippet_quality("Basic.asmx", ["/WS/Basic/Basic.asmx"]), STRONG)

    def test_percent_encoding_is_not_a_left_boundary(self):
        # In `%3dASC%26`, `3dASC` starts inside the %3d encoding.
        self.assertEqual(snippet_quality("3dASC", ["direction%3dASC%26page"]), WEAK)

    def test_at_least_ordering(self):
        self.assertTrue(at_least(STRONG, WEAK))
        self.assertTrue(at_least(MEDIUM, MEDIUM))
        self.assertFalse(at_least(WEAK, MEDIUM))
        self.assertFalse(at_least(MEDIUM, STRONG))


class TestBoundaryDetection(unittest.TestCase):
    def test_query_delimiters_count_as_boundaries(self):
        # `qzv=` anchored by '?' on the left and '=' on the right.
        self.assertTrue(at_least(snippet_quality("qzv", ["/x?qzv=7"]), MEDIUM))

    def test_multiple_occurrences_any_anchored_wins(self):
        # 'qz' appears mid-token once and anchored once; the anchored
        # occurrence should lift it to MEDIUM.
        self.assertTrue(at_least(snippet_quality("qz", ["/zqz/qz/"]), MEDIUM))


class TestMatchQuality(unittest.TestCase):
    def test_unanchored_hit_in_traffic_downgrades_to_weak(self):
        # Anchored in the template, but landing mid-token in the URI.
        self.assertEqual(match_quality("saml", MEDIUM, "/xsamly"), WEAK)
        self.assertEqual(match_quality("mgmt", STRONG, "/xmgmtx"), WEAK)

    def test_anchored_hit_in_traffic_keeps_grade(self):
        self.assertEqual(match_quality("saml", MEDIUM, "/saml/login"), MEDIUM)
        self.assertEqual(match_quality("mgmt/tm", STRONG, "/mgmt/tm/util/bash"), STRONG)

    def test_long_snippet_keeps_grade_unanchored(self):
        s = "PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ"
        self.assertEqual(match_quality(s, STRONG, "x" + s + "y"), STRONG)

    def test_weak_stays_weak(self):
        self.assertEqual(match_quality("e64/", WEAK, "/base64/e64/"), WEAK)


if __name__ == "__main__":
    unittest.main()
