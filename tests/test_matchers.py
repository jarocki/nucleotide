import unittest

from nucleotide.matchers import extract_dns_queries, extract_response_signals


class TestMatchers(unittest.TestCase):
    def test_extract_word_and_regex_from_http_matchers(self):
        doc = {
            "http": [
                {
                    "matchers": [
                        {
                            "type": "word",
                            "part": "header",
                            "words": ["x-jenkins:", "Jenkins"],
                        },
                        {
                            "type": "regex",
                            "regex": [r"(?i)Stable.tag:\s?([\w.]+)"],
                        },
                        {
                            "type": "status",
                            "status": [200, 302],
                        },
                    ]
                }
            ]
        }
        out = extract_response_signals(doc)
        self.assertEqual(out["response_words"], ["x-jenkins:", "Jenkins"])
        self.assertEqual(out["response_regexes"], [r"(?i)Stable.tag:\s?([\w.]+)"])
        self.assertEqual(out["response_status_codes"], [200, 302])
        # Sites carry location + part for downstream signature routing.
        self.assertEqual(out["response_word_sites"][0]["location"], "http[0]")
        self.assertEqual(out["response_word_sites"][0]["part"], "header")

    def test_extract_signals_from_dns_and_tcp_blocks(self):
        doc = {
            "dns": [{"matchers": [{"type": "word", "words": ["NXDOMAIN"]}]}],
            "tcp": [{"matchers": [{"type": "word", "words": ["redis_version"]}]}],
        }
        out = extract_response_signals(doc)
        self.assertEqual(set(out["response_words"]), {"NXDOMAIN", "redis_version"})
        sites = {s["location"]: s["word"] for s in out["response_word_sites"]}
        self.assertEqual(sites.get("dns[0]"), "NXDOMAIN")
        self.assertEqual(sites.get("tcp[0]"), "redis_version")

    def test_extract_dsl_kept_verbatim(self):
        doc = {
            "ssl": [{"matchers": [{"type": "dsl", "dsl": ["expired == true"]}]}]
        }
        out = extract_response_signals(doc)
        self.assertEqual(out["response_dsl"], ["expired == true"])

    def test_extract_dns_queries(self):
        doc = {
            "dns": [
                {"name": "{{FQDN}}", "type": "A"},
                {"name": "_dmarc.{{FQDN}}", "type": "TXT"},
            ]
        }
        out = extract_dns_queries(doc)
        self.assertEqual(
            out,
            [
                {"type": "A", "name": "{{FQDN}}"},
                {"type": "TXT", "name": "_dmarc.{{FQDN}}"},
            ],
        )

    def test_extract_returns_empty_for_blocks_without_matchers(self):
        self.assertEqual(extract_response_signals({}), {})
        self.assertEqual(extract_dns_queries({}), [])


if __name__ == "__main__":
    unittest.main()
