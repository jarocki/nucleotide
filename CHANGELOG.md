# Changelog

All notable changes to nucleotide are logged here. The project follows
[Semantic Versioning](https://semver.org).

## 1.0.0 — 2026-07-03

First stable release. The scope has expanded well beyond the initial
"URL to Nuclei template lookup" — nucleotide now emits tier-scoped
Snort/Suricata + Sigma detection rules and produces portable actor
behavior fingerprints from batches of observed events.

### Added

- **Actor fingerprint pipeline** (`nucleotide fingerprint`,
  `compare`, `match`). Turns a JSONL of observed events into a
  portable YAML artifact that captures:
  - tool inference (nuclei / non-nuclei / unknown), with per-signal
    reasoning;
  - CLI-option inference (`-severity`, `-tags`, `-H` with shape
    detection, `-random-agent`, `-interactsh-server`, `-rate-limit`,
    `-bulk-size`, `-scan-strategy`);
  - template subset preference + novel-probe surfacing;
  - `structural_hash` for identity + drift tracking.
- **Signature tiering** — every emitted Snort rule is tagged with the
  observability tier it can be matched at (T1 URL log, T2 header,
  T3 body, T4 TLS, T5 response). `--snort-out-dir` writes per-tier
  files; the tier is recorded in the rule's `msg:`, `metadata:`, and
  filename.
- **Sigma renderer** for T1 (webserver access log) and T5 (proxy
  response log) — the two tiers a SIEM typically ingests.
  `--sigma-out` + `--sigma-out-dir` write flat and per-tier bundles.
- **`nucleotide.runtime`** module — Nuclei default UA regex + a slice
  of the `-random-agent` pool, publicly-operated interactsh callback
  hosts, tag-set helpers. All values are observable-in-traffic;
  no binary analysis or decompilation.
- **`nucleotide.matchers`** module — extracts response-side signal
  (`response_words`, `response_regexes`, `response_status_codes`,
  `response_dsl`, `dns_queries`) from every `matchers:` block across
  http / network / tcp / dns / ssl / code / headless / javascript.
- **32 real Nuclei templates** vendored under `tests/fixtures/` at
  pinned upstream commit `7c65e60`, with per-fixture "what it
  exercises" notes.
- **Full user guide** (`docs/user-guide.md`) covering the problem
  framing, install, five-step walkthrough, tier taxonomy, output
  schema, library API, and FAQ.
- **Two reproducible asciicasts** under `docs/demos/` (build + lookup;
  fingerprint + compare + match), each paired with the shell script
  that produced it.

### Changed

- `signatures["snort"][tid]` is now `list[{tier, rule}]` (was
  `list[str]`). YARA output shape unchanged.
- `build_lookup` output now includes `signatures.sigma` alongside
  `yara` and `snort`.
- Templates whose `path:` is `{{BaseURL}}{{X}}` and whose `payloads:`
  block defines `X` are **materialized** — every payload value is
  substituted into the placeholder before chunking, so
  `laravel-env`, `generic-linux-lfi`, `xss-fuzz` (and any other
  template that hides its detection surface in a payload list) emit
  usable URI signatures.
- URI-anchor cap raised from 2 to 6 per template; anchors that are
  strict substrings of an already-picked anchor are dropped.
- Header value filtering is now value-driven, not name-driven:
  distinctive payloads (Struts2 OGNL Content-Type, Log4j JNDI
  headers, etc.) survive the "generic headers" filter that
  previously silently dropped them.
- Cookie parsing validates each name against RFC 6265 tokens;
  values that fail (Shellshock-style bash payloads in `Cookie:`)
  fall back to an opaque single-entry list with the full byte
  string preserved.
- OAST before/after context is clamped at the surrounding literal
  chunk boundary, so back-to-back `{{interactsh-url}}` markers
  don't bleed neighbouring-placeholder bytes into the anchor.
- Severity now maps to the Snort `classtype`
  (critical/high → `web-application-attack`, medium → `violation`,
  etc.).
- Snort SIDs are de-conflicted across the entire bundle — a build
  never emits two rules with the same SID.
- `extract_fingerprints` now also scans the request-target of raw
  HTTP requests for OAST callbacks (previously only header values,
  bodies, and `path:` blocks were scanned).
- `nucleotide.__init__` now exposes `fingerprint`,
  `parse_events_jsonl`, `to_yaml`, and the tier constants.

### Fixed

- The `_yara_name` slug was previously not guaranteed to start with
  a letter/underscore; templates whose id started with a digit
  produced invalid YARA rule names.
- `_match_score` no longer returns 1.0 when supporting-signal count
  outweighs contradictions — 1.0 is now reserved for
  `structural_hash` identity, and any contradiction caps the score
  at 0.95.

## 0.1.0 — early prototype

- Initial URL-snippet lookup builder + per-template YARA/Snort emitter.
- Two subcommands: `build`, `lookup`.
- Vendored an initial set of four real Nuclei templates for testing.
