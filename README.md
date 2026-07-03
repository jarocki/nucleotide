# nucleotide

Reverse-engineer threat-actor tool-and-CLI-option choices from observed
[Nuclei](https://github.com/projectdiscovery/nuclei-templates) traffic and
emit them as portable, diffable YAML fingerprints — plus tier-scoped
Snort/Suricata + Sigma detection rules for the request and response
surface every Nuclei template describes.

**nucleotide is not an IDS, not a SIEM, and not a scanner.** It reads
Nuclei template YAML, mines it for the byte patterns and behaviors an
attacker leaves behind when they run those templates, and turns that
signal into three things you can keep, share, and diff:

1. A **URL-to-template lookup** — given a URL from an access log, name
   the template that most likely produced it.
2. **Tier-scoped detection rules** — Snort/Suricata and Sigma, sorted
   by the observability tier that can match them (URL log, WAF, PCAP
   with/without SSL, response log).
3. **An actor-behavior fingerprint YAML** — given a batch of events an
   operator has grouped as "one actor," recover the Nuclei CLI
   options they picked (`-tags`, `-severity`, `-H`, `-random-agent`,
   `-interactsh-server`, `-scan-strategy`, `-rate-limit`, ...), the
   template subset they favor, and any Nuclei-shaped probes that
   didn't match a known template (potential custom templates).

## Install

```sh
git clone https://github.com/jarocki/nucleotide
cd nucleotide
pip install -e .
```

Requires Python 3.10+ and PyYAML. These the only dependencies.

## Demos

Two asciicasts demo videos are in `docs/demos/`:

```sh
asciinema play docs/demos/build-and-lookup.cast
asciinema play docs/demos/fingerprint-actor.cast
```

Both are reproducible — the shell script that produced each cast is
right next to it (`docs/demos/*.sh`).

## Quick tour

**Build the lookup and per-tier rule bundles:**

```sh
nucleotide build \
    --templates-dir /path/to/nuclei-templates \
    --out lookup.json \
    --snort-out-dir rules/snort/ \
    --sigma-out-dir rules/sigma/
```

Example output for 32 sampled Nuclei templates:

```
Wrote lookup.json | templates=32 snippets=26 unresolved=2 yara=31
                    snort[T1=107 T2=50 T3=3 T5=29]
```

**Attribute a URL to a template:**

```sh
$ nucleotide lookup lookup.json \
      https://victim.example/wp-content/plugins/akismet/readme.txt
https://victim.example/wp-content/plugins/akismet/readme.txt \
  UNIQUE  wordpress-akismet  s/ak  info  Akismet Anti-spam' ...
```

**Fingerprint an actor from a batch of events:**

```sh
nucleotide fingerprint events.jsonl \
    --lookup lookup.json \
    --actor-id apt-recon-2026Q3 \
    --out actor.yml
```

**Compare two fingerprints, or match a fresh batch against a saved one:**

```sh
nucleotide compare  ref-actor.yml new-actor.yml
nucleotide match    new-events.jsonl ref-actor.yml --lookup lookup.json
```

A full usage walkthrough, JSONL event schema, tier taxonomy, output-format
reference, and library API can be found in the User Guide: **[`docs/user-guide.md`](docs/user-guide.md)**.

## Signature tiers

Every emitted rule is tagged with the observability tier a consumer
of that data source could actually match:

| Tier | Consumer                                       | Anchor buffers                                                     |
| ---- | ---------------------------------------------- | ------------------------------------------------------------------ |
| T1   | Access / CDN / DNS log                         | `http_uri`, `cs-uri-stem`, DNS query name, TCP request byte-sig    |
| T2   | WAF, SSL-intercepting proxy                    | `http_user_agent`, `http_header`, `http_cookie`                    |
| T3   | Decrypted or cleartext PCAP                    | `http_client_body`, network payloads                               |
| T4   | TLS-opaque PCAP                                | JA3 / JA4 (`alert tls; ja3.hash;`)                                 |
| T5   | Outbound proxy, honeypot response cache        | `flow:to_client`, `sc-response-body`                               |

`--snort-out-dir DIR/` writes `nuclei-t1.rules` … `nuclei-t5.rules`.
`--sigma-out-dir DIR/` writes `nuclei-t1.yml` and `nuclei-t5.yml` (the
two tiers a SIEM typically ingests).

Deploy each tier at the vantage point that can see its buffer.

## What nucleotide extracts from a Nuclei template

For every template in the corpus:

- **Longest literal URL chunks** (with `payloads:` blocks materialized
  so `path: {{BaseURL}}{{X}}` + `payloads: X: [/.env, /.env.bak, ...]`
  yields real detection surface).
- **Ordered request headers, in original send order**, with values
  reduced to their longest literal substring when they carry Nuclei
  placeholders. Payload-shaped values (Struts2 OGNL, Log4j JNDI, etc.)
  are kept verbatim; routine values (`application/json`) are filtered.
- **Cookies** parsed from both `headers:` and `raw:` request blocks,
  with an RFC 6265 fallback for Shellshock-style bash payloads in
  `Cookie:`.
- **OAST callback injection points** — every `{{interactsh-*}}` /
  `{{oast-*}}` occurrence, with its location (header, body, path,
  raw URI, network input) and clamped literal byte context around it.
- **Response matchers** — `words:` / `regex:` / `status:` / `dsl:`
  from every `matchers:` block across http/network/tcp/dns/ssl.
- **DNS queries**, **TCP byte signatures**, **TLS hints**, and — when a
  template supplies a fully-specified ClientHello — **JA3 / JA4** hashes.

## Test suite

```sh
python -m unittest discover -s tests
```

104 tests, all against real Nuclei templates vendored under
`tests/fixtures/` (see [that directory's README](tests/fixtures/README.md)
for per-fixture notes on what each one exercises).

## License

Apache 2.0. See [LICENSE](LICENSE).
