# nucleotide

Build a URL-snippet lookup table that maps observed URLs back to the
[Nuclei template](https://github.com/projectdiscovery/nuclei-templates) they
came from, plus a per-template *fingerprint* (User-Agent, ordered headers,
cookies, body/raw hashes, OAST callback injection points, network byte
signatures, TLS hints) and ready-to-deploy **YARA** and **Snort/Suricata**
signatures.

Given a URL pulled from logs, honeypot traffic, or a WAF rule, `nucleotide`
answers: *which Nuclei template most likely produced this request?* — and
gives you signatures you can drop into a YARA scan or an IDS to catch the
same probe on the wire.

## How it works

1. **Fetch** a Nuclei templates tree (`git clone --depth 1`, with a tarball
   fallback when `git` isn't available).
2. **Parse** every `*.yaml` / `*.yml` template, normalize its request paths
   (both `path:` and `raw:` blocks), and strip Nuclei placeholders
   (`{{BaseURL}}`, `{{Hostname}}`, ...) to leave only the literal substrings.
3. **Compute the shortest unique substring** for each template across the
   whole corpus. Templates that share all substrings with another template
   end up in `unresolved`; templates with no HTTP path (network-only,
   DNS-only) are reported as `no_url`. Templates whose paths look like
   `{{BaseURL}}{{X}}` and define `X` under a `payloads:` block (`/.env`,
   `/.env.bak`, `/etc/passwd`, URL-encoded XSS variants, etc.) are
   **materialized** first — each payload value is substituted into the
   placeholder so the real detection surface enters the chunk set.
4. **Extract fingerprints** per template from the *full payload*, not just
   the URL:
   - **User-Agents** — every explicit UA value.
   - **Headers, in send order** — order-preserving capture of every custom
     header (`header_order`, `header_order_signature`) on top of the legacy
     name-folded sorted hash (`header_signature`).
   - **Cookies** — names + values parsed out of every `Cookie:` header
     (`cookies`, `cookie_names`, `cookie_signature`), including cookies that
     live inside `raw:` request blocks. Values whose segments fail RFC 6265
     cookie-name validation (Shellshock-style bash payloads in `Cookie:`)
     fall back to an opaque single-entry list with the full value preserved.
   - **OAST callback injection points** — every occurrence of
     `{{interactsh-*}}` / `{{oast-*}}` is recorded with its location
     (header, body, path, raw URI, raw body, network input) and the literal
     byte context immediately before and after the marker (`oast_injections`,
     `oast_locations`, `oast_placeholders`, `oast_signature`). The
     before/after slice is clamped to the surrounding literal chunk so
     back-to-back placeholders (`{{X}}sep{{X}}sep{{X}}...`, common in
     parameter-fuzzing templates) don't bleed a neighbouring placeholder's
     bytes into the anchor.
   - **Response-side matchers** — `words:` / `regex:` / `status:` / `dsl:`
     entries pulled from every `matchers:` block across `http`, `network`,
     `tcp`, `dns`, `ssl`, and other probe blocks
     (`response_words`, `response_word_sites`, `response_regexes`,
     `response_regex_sites`, `response_status_codes`, `response_dsl`).
   - **DNS probes** — for `dns:` blocks, the queries the template issues
     (`dns_queries`, `dns_record_types`, `dns_names`).
   - **Body / raw-request hashes**, **network byte signatures** (hex + string),
     **TLS hints**, and — only when the template fully specifies a
     ClientHello — **JA3 / JA4** hashes.
   - **`request_shape`** — single rolled-up digest over methods, ordered
     headers, cookies, body/raw hashes, and OAST injection sites.
5. **Generate signatures** — for each template that carries enough signal,
   nucleotide emits:
   - a **YARA rule** anchored on the longest literal URL chunk (not the
     shortened lookup-only snippet), distinctive payload-bearing header
     values (Struts2 OGNL, Log4j JNDI, Shellshock bash), cookie names, OAST
     pre/post context bytes, response-side words from `matchers:` blocks,
     and DNS query names;
   - a set of **Snort/Suricata rules** with content matches on
     `http_uri`, `http_user_agent`, `http_header`, `http_cookie`,
     `http_client_body`, plus `flow:to_client` rules for response-side
     anchors (so the IDS catches *successful* probes, not just attempts).
     Severity is mapped to the Snort `classtype` (`critical`/`high` →
     `web-application-attack`, etc.) and SIDs are de-conflicted globally
     so a build never emits two rules with the same SID.
6. **Lookup** — against the resulting JSON, match a URL by its unique snippet
   first (`UNIQUE`), then optionally by shared-path chunks (`AMBIGUOUS`).

### Header value filtering

Header anchors are chosen by *value distinctiveness*, not header name:
- `Content-Type: application/json` is filtered out as routine.
- `Content-Type: %{(#test='multipart/form-data')...}` (the Struts2 OGNL
  RCE) is kept verbatim — its payload markers (`${`, `%{`, `() {`, etc.),
  length, or non-ASCII bytes flag it as payload-bearing.
- `Authorization: Bearer {{interactsh-url}}` is reduced to the literal
  substring `Bearer ` and kept only if that meets the minimum anchor length.

`User-Agent:` and `Cookie:` are normally handled by dedicated extractors,
but when their *values* are payload-like (Shellshock weaponizes both) they
also emit as raw header anchors so the bash bytes survive.

### A note on JA3 / JA4

JA3 and JA4 describe a TLS client's ClientHello, which is a property of the
Nuclei runtime, not of the YAML template. We emit a real JA3/JA4 only for
the rare template that specifies enough TLS configuration to nail down a
ClientHello; otherwise we expose `tls_hints` and a `request_shape` digest
that play the same role for the layer the template actually controls.

## Install

```sh
pip install .
```

Requires Python 3.10+ and `pyyaml`.

## Usage

### Build the lookup table

Fetch the upstream `projectdiscovery/nuclei-templates` repo and write a
lookup file (plus YARA and Snort rules):

```sh
nucleotide build \
    --out nucleotide-lookup.json \
    --yara-out nuclei.yar \
    --snort-out nuclei.rules
```

Use a local templates tree instead of fetching:

```sh
nucleotide build --templates-dir /path/to/nuclei-templates --out lookup.json
```

Reuse a previously cached clone without pulling updates:

```sh
nucleotide build --no-fetch --out lookup.json
```

Tune the minimum snippet length (raise it for higher precision against noisy
log traffic):

```sh
nucleotide build --min-len 8 --out lookup.json
```

### Query URLs

Pass URLs as arguments:

```sh
nucleotide lookup lookup.json \
    https://victim.example/wp-content/plugins/foo-bar/readme.txt
```

Or pipe them in on stdin:

```sh
cat access.log | awk '{print $7}' | nucleotide lookup lookup.json
```

Only report 1:1 unique-snippet matches, suppressing shared-path hits:

```sh
nucleotide lookup --strict lookup.json < urls.txt
```

Output is tab-separated:

```
<query>  UNIQUE|AMBIGUOUS|NO_MATCH  <template_id>  <snippet>  <severity>  <name>
```

### Example signatures

A template that does an SSRF probe with an OAST callback in its JSON body
produces a YARA rule like:

```
rule nuclei_ssrf_oast_probe
{
    meta:
        nuclei_id = "ssrf-oast-probe"
        severity = "high"
        nuclei_name = "Generic SSRF OAST Callback"
    strings:
        $ua_0 = "User-Agent: NucleotideProbe/1.0"
        $hdr_1 = "X-Trace-Id: abcdef-12345"
        $hdr_2 = "Cookie: sid=abc123; tracker=xyz"
        $ck_3 = "sid="
        $ck_4 = "tracker="
        $oast_pre_5 = "{\"callback\":\"http://"
        $oast_post_6 = "/cb\",\"probe\":\"trail-mark"
    condition:
        any of them
}
```

And Snort/Suricata rules like:

```
alert http any any -> any any (msg:"Nuclei ssrf-oast-probe (URI snippet)"; flow:established,to_server; content:"/api/v2/ssrf"; http_uri; nocase; sid:1536579; rev:1; classtype:web-application-activity;)
alert http any any -> any any (msg:"Nuclei ssrf-oast-probe (User-Agent)"; flow:established,to_server; content:"NucleotideProbe/1.0"; http_user_agent; sid:1102555; rev:1; classtype:web-application-activity;)
alert http any any -> any any (msg:"Nuclei ssrf-oast-probe (cookie sid)"; flow:established,to_server; content:"sid="; http_cookie; sid:1881897; rev:1; classtype:web-application-activity;)
alert http any any -> any any (msg:"Nuclei ssrf-oast-probe (OAST pre @ http[0].body)"; flow:established,to_server; content:"{|22|callback|22|:|22|http://"; http_client_body; sid:1678775; rev:1; classtype:web-application-activity;)
```

Notes:

- Snort SIDs live in the 1_000_000–1_899_999 range and are derived
  deterministically from `sha256(template_id, salt)`, so successive
  rebuilds don't churn them.
- Snort `content:` strings are hex-encoded for any non-printable byte or
  reserved character (`"`, `;`, `\`, `|`).
- Header values that still carry an unresolved `{{...}}` placeholder are
  *skipped* when emitting static signatures — Nuclei fills those in at
  runtime, so they aren't useful as wire-level anchors.
- The YARA condition is `any of them`; tighten to `all of them` or
  `N of ($hdr_*, $ck_*)` in post-processing if you want stricter behavior.

## Output schema

The JSON written by `build` has five top-level keys:

- `metadata` — generation timestamp, source URL, git commit (if available),
  template counts, snippet counts, `min_snippet_len` used.
- `templates` — keyed by template id (with `@<file>` disambiguation when
  ids collide); each entry carries `name`, `severity`, `tags`, `file`,
  `paths`, literal `chunks`, `url_snippet`, and `fingerprints` (with all of
  the fields listed in "How it works" §4).
- `snippet_index` — `{snippet: template_id}` for fast reverse lookup.
- `unresolved` — template ids that share all their substrings with another
  template, or have no URL surface to fingerprint at all.
- `signatures` — `{"yara": {tid: rule_text}, "snort": {tid: [rule, ...]}}`
  for every template that carries usable wire signal.

## Library use

```python
from pathlib import Path
from nucleotide import build_lookup

result = build_lookup(Path("/path/to/nuclei-templates"))
print(result["metadata"]["resolved_snippets"])
print(result["signatures"]["yara"]["wp-foo-plugin"])
```

## Tests

```sh
python -m unittest discover -s tests -v
```

The test fixtures under `tests/fixtures/` are tiny synthetic Nuclei
templates that exercise:

- the HTTP `path:` block (`wp-foo.yaml`, `wp-bar.yaml`),
- the `raw:` request block (`api-quux.yaml`),
- a network-only template with no URL surface (`network-redis.yaml`), and
- a full payload template with ordered custom headers, cookies, and an OAST
  callback in the JSON body (`ssrf-oast.yaml`).

## License

Apache 2.0. See [LICENSE](LICENSE).
