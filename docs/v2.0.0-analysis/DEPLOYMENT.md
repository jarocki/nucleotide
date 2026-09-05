# Nucleotide v1.0.0 False-Positive Regression Patch

## Overview

This patch fixes four coordinated false-positive classes discovered when nucleotide v1.0.0 was run against real capture datasets (Honeynet T-Pot Log4Shell 2021, galah LLM-honeypot 2024).

**Root cause:** The original `compute_unique_snippets` algorithm selected the globally shortest unique substring per template. On a 13k-corpus this produces 4-byte fragments torn from the middle of longer literals — `e64/` from `base64/`, `//19` from `http://192...`, `edis` from `redis` — which re-appear in unrelated adversarial traffic, triggering confident-but-bogus template matches that cascade into actor/tool attribution errors.

**Key finding:** Empirically, **anchoring (not length) is the clean separator.** All five red herrings are unanchored mid-token fragments. All legit short path tokens (`saml` in `/saml/login`, `mgmt` in `/mgmt/tm/util/bash`) sit on `/` boundaries.

## Changes

### 1. `nucleotide/quality.py` (new module)

Grades each resolved snippet WEAK / MEDIUM / STRONG. Anchoring on path
boundaries is the primary axis; snippets under 8 bytes whose every
alphanumeric segment is hex-only or a common English word are stopped
(`is_generic_token`); `match_quality` downgrades a hit whose snippet lands
mid-token in the URI. Exports `at_least(quality, floor)`, `edge_anchored`,
`match_quality`, `is_generic_token`, `common_words`.

### 2. `nucleotide/snippets.py`

Two-pass selection: shortest anchored, non-generic unique substring first;
unanchored fallback only when no such candidate exists. Measured changes
on the corpus are tabulated in ANALYSIS.md §3.1 (`wordpress-akismet` `s/ak`
→ `akismet`, `open-proxy-internal` `//19` → `/ntp`,
`landray-eis-ws-infoleak` `WS/B` → `WS/Basic`, …).

### 3. `nucleotide/build.py`

Grades every resolved snippet at build time; stores the grade on template
metadata and in a top-level `snippet_quality` map; prints
`quality[strong=N medium=N weak=N]`.

### 4. `nucleotide/actor.py`

- `classify_event(event, lookup, min_quality=MEDIUM)` returns
  `matched_templates` (all) and `trustworthy_templates` (hits at or above
  `min_quality` after `match_quality`).
- `fingerprint(events, lookup, actor_id=None, min_quality=MEDIUM)`: tool
  inference, `-severity`, `-tags`, and the structural hash use trustworthy
  hits only; `low_signal` is set when there are none and no Nuclei UA/OAST
  signal; low-signal hashes fold in rate limit, header names, scan
  strategy, User-Agent shapes, and URI shapes.
- `template_preference` lists `matched` (trustworthy), `weak_only_matches`,
  and `hits_by_template` for the trustworthy subset.

### 5. `nucleotide/cli.py`

- `lookup --min-quality {weak,medium,strong}` (default `weak`); seventh
  output column is the per-hit grade after `match_quality`.
- `fingerprint --min-quality` and `match --min-quality` (default `medium`).
- `_match_score` caps at 0.5 when both fingerprints are `low_signal`.

### 6. `nucleotide/data/`

`common-words.txt` (28,338 words, wordfreq 3.1.1, Zipf ≥ 3.0) and
`regen_common_words.py`. wordfreq is a regeneration-time dependency only.

### 7. Tests

- `test_quality.py` (18): fragments grade WEAK; `saml`/`mgmt`/`akismet`
  grade MEDIUM+; `Basic`/`login`/`6100`/`3d50`/`ffff` grade WEAK when
  anchored; `%XX` is not a left boundary; `match_quality` cases.
- `test_regression_false_positives.py` (14): cascade prevention on a
  synthetic corpus; Nuclei-UA positive control; low-signal hash
  divergence by rate and by shape; generic-token selection; JNDI and
  hex-string URIs do not attribute; `min_quality="strong"`.
- One test in `test_snippets.py` (`test_prefers_shortest_anchored`).

**All 137 tests pass.**

## Deployment

### Breaking Changes

**Minor:** Lookup output now has a 7th column (quality tier). Scripts parsing column-6 will break; adjust to `{0-5}.*{quality_tier}` or switch to `--strict` mode (UNIQUE + AMBIGUOUS only, quality tier omitted).

### Backward Compatibility

- Lookups built with old nucleotide will still work (quality defaults to weak)
- Fingerprints from old builds load fine; new `low_signal` field will be absent, treating them as unknown-signal
- `match` against old fingerprints will score conservatively (no hash collision without quality data)

### Recommended Deployment Path

1. Rebuild your lookup with the new nucleotide: `nucleotide build --out lookup-new.json ...`
   - Review the `quality[strong=X medium=Y weak=Z]` summary. Measured on the 13,611-template corpus on 2026-09-04: strong=5303, medium=1620, weak=29 (see MEASUREMENTS.md)
   
2. Run `lookup` with `--min-quality strong` and `--min-quality medium` on a sample of your real traffic
   - On the Log4Shell set, both gates yield 1 UNIQUE row (`img/favicon`, STRONG); on galah, `medium` yields 18 and `strong` yields 10. Decide which gate fits your traffic before alerting on MEDIUM hits
   - Verify that legit probes (Nuclei scans with correct UA) still match expected templates

3. Cut a new fingerprint baseline on a known actor's events
   - Compare against old baseline: expect `low_signal` to flip to false for real Nuclei users, unchanged for unknowns

4. Swap over production lookups; roll forward new fingerprints

### Validating the Fix

**Pre-patch behavior (broken):**
```bash
nucleotide lookup lookup-v1.json \
  < log4shell-uris.txt
# Output: many matches on httpbin-xss, open-proxy-internal via weak snippets
# Actor fingerprint: likely_tool=nuclei (false positive on 4-byte fragments)
```

**Post-patch behavior (fixed):**
```bash
nucleotide lookup lookup-v2.json \
  < log4shell-uris.txt
# Output: same matches but graded WEAK in 7th column
# Actor fingerprint: likely_tool=unknown (curl + no Nuclei runtime signal wins)
```

## Known Limitations

1. **Long unanchored snippets (≥12 bytes):** Grade MEDIUM without anchoring. On the 2.0.0 build no resolved snippet takes this path (all 1,620 MEDIUM snippets are anchored and shorter than 8 bytes), so the rule is untested on the corpus.

2. **Shared anchored substrings:** Two distinct templates (e.g., two Wordpress plugins) both with `/plugins/` won't resolve if `/plugins/` is shared and longer substrings are also shared — both fall unresolved. Frequency not measured.

3. **Query-parameter bounds:** The `_BOUNDARY` set includes `?`, `=`, `&` but not braces or other delimiters. Percent-encoded input is not decoded; only the `%XX`-is-not-a-left-boundary rule addresses it.

4. **Common-word list:** English only, frequency-based (Zipf ≥ 3.0). Product names that are also common words (`telescope`, `pools`) are stopped even when they are the distinctive path component; the template then resolves on a longer snippet or falls to WEAK.

5. **Short anchored tokens that are neither hex nor common words** (`/ntp`, `/SDK`, `m3u8`) still grade MEDIUM. Use `--min-quality strong` where that is too permissive for the traffic.

## Implementation Notes for Reviewers

- **Anchoring detection** is single-pass linear scan per snippet; O(snippet_len × chunk_len). Acceptable on 8.9k chunks, ~100MB in memory.
- **Quality grading** happens at build time (once), not runtime. Negligible cost.
- **Trustworthy filtering** in actor inference is lazy: `trustworthy_templates = [t for t in matched if quality[snippet] >= MEDIUM]` inside classify_event, no separate data structure.

## Testing Checklist

- [x] All 104 existing tests still pass
- [x] 2 new test modules (32 tests) plus 1 added to test_snippets.py; 137 total, all passing
- [x] Snippet quality measured on full 13,611-template corpus: strong=5303, medium=1620, weak=29 (resolved snippets only)
- [x] Log4Shell capture set (686 events, 75 IPs) re-fingerprinted: all 11 actors `unknown`/`low_signal`, 9 distinct hashes (1.0.0: 3, with 9 actors sharing one); the 2 actors mislabelled nuclei in 1.0.0 are no longer mislabelled
- [x] galah 2024 capture set (63 events) run through lookup: UNIQUE rows 37 → 18; 33 of the 34 distinct 1.0.0 snippets were 4–5 bytes long, all gone

## References

- **Original failing case:** `open-proxy-internal` snippet `//19` matching JNDI callbacks to `192.168.x.x` (Log4Shell 2021)
- **Unit-test separation:** `tests/test_quality.py` asserts that `e64/`, `//19`, `edis`, `on-3` grade WEAK and that `saml`, `mgmt`, `akismet` grade MEDIUM or better in their parent chunks. It also asserts that `Basic`, `login`, `6100`, `3d50`, and `ffff` grade WEAK even when anchored, and that `match_quality` downgrades a hit that lands mid-token in the URI
- **Anchor-to-boundary characters:** `/?=&.:;,%+ ` (slash, question, equals, ampersand, period, colon, semicolon, comma, percent, plus, space)
