# Changelog

All notable changes to nucleotide are logged here. The project follows
[Semantic Versioning](https://semver.org).

## 2.0.0 — 2026-09-04

Quality-graded snippets, generic-token stop, match-time anchoring, and
low-signal actor handling. Motivated by false-positive template matches
found when running 1.0.0 against real capture data. The full analysis,
with every figure measured and the commands that produced it, is in
`docs/v2.0.0-analysis/`.

### Why a major version

- `lookup` output gains a seventh column (snippet quality); scripts that
  parse by position will break.
- Fingerprints gain `low_signal` and `template_preference.weak_only_matches`.
- Structural hashes change for actors with no trustworthy template hits
  (rate limit, header names, scan strategy, User-Agent shapes, and URI
  shapes are folded in), so 1.0.0 hashes and `actor-<hash>` ids for those
  actors do not carry over.
- `classify_event` and `fingerprint` take a `min_quality` keyword and
  return/use `trustworthy_templates`; attribution no longer reads
  `matched_templates`.
- Lookups built by 1.0.0 load in 2.0.0 (every snippet is treated as WEAK);
  lookups built by 2.0.0 are not usable by 1.0.0.
- Snippet selection changed for many templates; a 2.0.0 lookup is not
  byte-comparable with a 1.0.0 lookup.

### Added

- `nucleotide/quality.py`: `snippet_quality(snippet, parent_chunks)` grades
  a snippet WEAK, MEDIUM, or STRONG. Anchoring on path boundaries
  (`/?=&.:;,%+` and space) is the primary axis; STRONG = anchored and
  ≥ 8 bytes; MEDIUM = anchored and not a generic token, or unanchored and
  ≥ 12 bytes. `is_generic_token` stops snippets under 8 bytes whose every
  alphanumeric segment is hex-only or a common English word.
  `match_quality(snippet, grade, uri)` downgrades a hit to WEAK when a
  snippet under 12 bytes lands mid-token in the URI. `edge_anchored` is
  the single anchoring implementation, shared with `snippets.py`; a `%`
  followed by a hex pair is not a left boundary.
- `nucleotide/data/common-words.txt`: 28,338 alphabetic English words with
  Zipf frequency ≥ 3.0, generated from wordfreq 3.1.1 by
  `nucleotide/data/regen_common_words.py` (wordfreq is not a runtime
  dependency; the list is vendored).
- `lookup --min-quality {weak,medium,strong}` (default `weak`: report
  everything, label it). `fingerprint --min-quality` and
  `match --min-quality` (default `medium`).
- Fingerprint field `low_signal`: true when there are no template hits at
  or above `min_quality` and no Nuclei UA or default-OAST signal.
- Fingerprint field `template_preference.weak_only_matches`.
- `actor.shape_of_path`, `infer_path_shapes`, `shape_of_ua`,
  `infer_ua_shapes`: URI and User-Agent shapes (IPv4 → `A`, hex runs ≥ 8
  → `H`, base64-like runs ≥ 16 → `B`, digits → `N`) used as low-signal
  hash discriminators.
- Build summary prints `quality[strong=N medium=N weak=N]`; the lookup JSON
  carries `snippet_quality` per template and a top-level
  `snippet_quality_map`.
- Tests: `tests/test_quality.py` (18), `tests/test_regression_false_positives.py`
  (14), one in `tests/test_snippets.py`. 137 tests total, up from 104.
  Line coverage of `nucleotide/*`: 88%.

### Changed

- `snippets.py`: two-pass selection — shortest anchored, non-generic unique
  substring first; unanchored fallback only when no such candidate exists.
  On the 13,611-template corpus: `wordpress-akismet` `s/ak` → `akismet`;
  `httpbin-xss` `e64/` → a 60-byte `base64/…` string; `open-proxy-internal`
  `//19` → `/ntp`; `redis-config` `edis` → `redis`;
  `filebrowser-login-panel` `on-3` → `img/icons`; `landray-eis-ws-infoleak`
  `WS/B` → `WS/Basic`; `CVE-2023-40748` `%3dc` → `6100%3d6100`. Quality
  distribution: strong 5,303 / medium 1,620 / weak 29 (of 6,952 resolved).
- `actor.py`: tool inference, `-severity`, and `-tags` use hits at or above
  `min_quality` only; `_match_score` caps at 0.5 when both fingerprints are
  `low_signal`.
- `build`: 85.5 s → 94.9 s on the corpus above (single runs).

### Measured effect on capture data (details in docs/v2.0.0-analysis/)

- Log4Shell, 65 distinct URIs: UNIQUE rows 88 → 1 (the two 1.0.0 fragments
  `//19` and `e64/`, 41 URIs each, are gone; the remaining row is
  `img/favicon` on a favicon request).
- galah, 62 distinct URIs: UNIQUE rows 37 → 18; 33 of the 34 distinct
  1.0.0 snippets were 4–5 bytes long and none remain.
- Eleven Log4Shell actors: all 11 are `unknown` and `low_signal` with no
  inferred `-severity`/`-tags` (1.0.0: 2 labelled `nuclei` at 0.6); 9
  distinct structural hashes (1.0.0: 3, with 9 actors sharing one). The
  two pairs that share a hash have identical UA shapes, URI shapes, and
  rate limit.
- An intermediate build with anchoring but without the generic-token stop
  and match-time check was measured and rejected: on Log4Shell it replaced
  `//19`/`e64/` with `Basic` (41 URIs) and `6100` (11) and left the same
  two actors labelled `nuclei`. Its figures are kept in the analysis for
  comparison.

### Known limitations

- Short anchored tokens that are neither hex nor common English words
  (`/ntp`, `/SDK`, `m3u8`) still grade MEDIUM; `--min-quality strong` is
  the conservative gate.
- The common-word list is English only; product names that are also
  common words (`telescope`, `pools`) are stopped.
- Percent-encoded input is not decoded before snippet selection.
- Low-signal discriminators cannot separate actors with identical UA
  shapes, URI shapes, and rate limit.
- No genuine Nuclei actor exists in either capture set; Nuclei-UA
  attribution is covered by unit tests only.

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
