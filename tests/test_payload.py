import unittest

from nucleotide.payload import (
    find_oast_injections,
    literal_chunks,
    longest_literal,
    parse_cookie_header,
    parse_raw_request,
)


class TestPayload(unittest.TestCase):
    def test_parse_raw_request_extracts_method_target_headers_body(self):
        raw = (
            "POST /api/v3/quux HTTP/1.1\n"
            "Host: target.example\n"
            "Content-Type: application/json\n"
            "User-Agent: Probe/1\n"
            "\n"
            '{"k":"v"}'
        )
        parsed = parse_raw_request(raw)
        self.assertEqual(parsed["method"], "POST")
        self.assertEqual(parsed["target"], "/api/v3/quux")
        self.assertEqual(
            parsed["headers"],
            [
                ("Host", "target.example"),
                ("Content-Type", "application/json"),
                ("User-Agent", "Probe/1"),
            ],
        )
        self.assertEqual(parsed["body"], '{"k":"v"}')

    def test_parse_raw_request_handles_blank_body(self):
        parsed = parse_raw_request("GET / HTTP/1.1\nHost: x\n")
        self.assertEqual(parsed["method"], "GET")
        self.assertEqual(parsed["headers"], [("Host", "x")])
        self.assertEqual(parsed["body"], "")

    def test_parse_raw_request_rejects_malformed(self):
        self.assertEqual(parse_raw_request(""), {})
        self.assertEqual(parse_raw_request("not an http line"), {})

    def test_parse_cookie_header_splits_on_semicolons(self):
        ck = parse_cookie_header(" sid=abc123 ; tracker=xyz ; flagged ")
        self.assertEqual(
            ck,
            [("sid", "abc123"), ("tracker", "xyz"), ("flagged", "")],
        )

    def test_find_oast_injections_yields_placeholder_with_context(self):
        text = "prefix-bytes-{{interactsh-url}}-suffix-bytes"
        out = find_oast_injections(text, "http[0].body")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["placeholder"], "{{interactsh-url}}")
        self.assertEqual(out[0]["location"], "http[0].body")
        self.assertEqual(out[0]["before"], "prefix-bytes-")
        self.assertEqual(out[0]["after"], "-suffix-bytes")

    def test_find_oast_injections_finds_multiple_variants(self):
        text = "{{interactsh-url}} and {{interactsh-md5}} and {{oast-id}}"
        out = find_oast_injections(text, "loc")
        placeholders = {o["placeholder"] for o in out}
        self.assertEqual(
            placeholders,
            {"{{interactsh-url}}", "{{interactsh-md5}}", "{{oast-id}}"},
        )

    def test_find_oast_injections_ignores_non_oast_placeholders(self):
        text = "{{BaseURL}}/x?{{Hostname}}"
        self.assertEqual(find_oast_injections(text, "loc"), [])

    def test_parse_cookie_header_falls_back_for_shellshock_payload(self):
        # The Shellshock cookie payload contains bash `;` separators which
        # would shred into garbage "cookie names" like `}` or `echo` if the
        # parser naively split on `;`. The RFC 6265 token check should
        # detect this and fall back to a single opaque (name="", value=...).
        payload = "() { ignored;}; echo /etc/passwd; /bin/cat /etc/passwd"
        out = parse_cookie_header(payload)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0][0], "")
        self.assertEqual(out[0][1], payload)

    def test_parse_cookie_header_accepts_well_formed_cookies(self):
        # Validation must still let real cookie lists through unchanged.
        ck = parse_cookie_header("session=abc; csrf=xyz")
        self.assertEqual(ck, [("session", "abc"), ("csrf", "xyz")])

    def test_literal_chunks_splits_on_nuclei_placeholders(self):
        self.assertEqual(
            literal_chunks("Bearer {{interactsh-url}} /cb"),
            ["Bearer ", " /cb"],
        )
        self.assertEqual(literal_chunks("{{x}}"), [])

    def test_longest_literal_picks_largest_chunk_above_threshold(self):
        self.assertEqual(
            longest_literal("Bearer-prefix-{{x}}-tiny", min_len=6),
            "Bearer-prefix-",
        )
        # Nothing meets the threshold -> None.
        self.assertIsNone(longest_literal("/a/{{x}}/b", min_len=6))


if __name__ == "__main__":
    unittest.main()
