# nucleotide

Build a URL-snippet lookup table that maps observed URLs back to the
[Nuclei template](https://github.com/projectdiscovery/nuclei-templates) they
came from, plus a per-template fingerprint (User-Agent, header/body hashes,
network byte signatures, TLS hints).

Given a URL pulled from logs, honeypot traffic, or a WAF rule, `nucleotide`
answers: *which Nuclei template most likely produced this request?*

## How it works

1. **Fetch** a Nuclei templates tree (`git clone --depth 1`, with a tarball
   fallback when `git` isn't available).
2. **Parse** every `*.yaml` / `*.yml` template, normalize its request paths
   (both `path:` and `raw:` blocks), and strip Nuclei placeholders
   (`{{BaseURL}}`, `{{Hostname}}`, ...) to leave only the literal substrings.
3. **Compute the shortest unique substring** for each template across the
   whole corpus. Templates that share all substrings with another template
   end up in `unresolved`; templates with no HTTP path (network-only,
   DNS-only) are reported as `no_url`.
4. **Extract fingerprints** per template: User-Agents, custom header
   signatures, body/raw-request hashes, network byte signatures (hex and
   string), TLS hints, and (only when the template fully specifies a
   ClientHello) JA3 / JA4 hashes.
5. **Lookup**: against the resulting JSON, match a URL by its unique snippet
   first (`UNIQUE`), then optionally by shared-path chunks (`AMBIGUOUS`).

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
lookup file:

```sh
nucleotide build --out nucleotide-lookup.json
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

## Output schema

The JSON written by `build` has four top-level keys:

- `metadata` — generation timestamp, source URL, git commit (if available),
  template counts, snippet counts, `min_snippet_len` used.
- `templates` — keyed by template id (with `@<file>` disambiguation when
  ids collide); each entry carries `name`, `severity`, `tags`, `file`,
  `paths`, literal `chunks`, `url_snippet`, and `fingerprints`.
- `snippet_index` — `{snippet: template_id}` for fast reverse lookup.
- `unresolved` — template ids that share all their substrings with another
  template, or have no URL surface to fingerprint at all.

## Library use

```python
from pathlib import Path
from nucleotide import build_lookup

result = build_lookup(Path("/path/to/nuclei-templates"))
print(result["metadata"]["resolved_snippets"])
```

## Tests

```sh
python -m unittest discover -s tests -v
```

The test fixtures under `tests/fixtures/` are tiny synthetic Nuclei
templates that exercise the HTTP `path:` block, the `raw:` request block,
and a network-only template (no URL surface).

## License

Apache 2.0. See [LICENSE](LICENSE).
