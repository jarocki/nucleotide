# nucleotide 1.0.0 → 2.0.0: False-Positive Analysis and Fix

Every number in this document was measured on 2026-09-04 against the same
template corpus (13,611 templates) and the same two capture sets, for three
builds: 1.0.0 (`d6dee5b`), an intermediate candidate that added anchoring
only (not released), and the 2.0.0 release commit. The commands that
produced each figure are in [MEASUREMENTS.md](MEASUREMENTS.md).

## 1. The problem in 1.0.0

`compute_unique_snippets` picks the shortest substring that is unique
across the template corpus. Uniqueness across 13,611 templates is not the
same as distinctiveness in live traffic: the shortest unique substring is
usually a fragment cut out of the middle of a token, and such fragments
recur in unrelated payloads.

Running the 1.0.0 lookup over the 65 distinct URIs in the Log4Shell capture
(Honeynet T-Pot, 2021-12-14 to 2021-12-16; 686 events; 75 source IPs) gave
88 UNIQUE rows. 82 of them came from two fragments:

| Snippet | Template | Parent chunk | URIs matched (of 65) |
|---|---|---|---|
| `//19` | open-proxy-internal | `http://192.168.0.1/` | 41 |
| `e64/` | httpbin-xss | `/base64/PHNjcmlw…` | 41 |

Both sit mid-token in their parent chunk. In the Log4Shell traffic they are
hit by JNDI callbacks to RFC-1918 addresses and by Base64-encoded command
payloads.

On the galah capture (63 events, 62 distinct URIs) 1.0.0 gave 37 UNIQUE
rows; 33 of the 34 distinct snippets involved were 4–5 bytes long
(`at.j`, `laca`, `dns-`, `ci/;`, `on/z`, `edis`, `ake-`, …), the 34th was
`in/../`.

### Downstream cascade

Fingerprinting the eleven Log4Shell actors that had at least 15 events with
1.0.0:

- 2 of 11 (`195.54.160.149`, `23.168.193.26`) were assigned
  `likely_tool: nuclei` (confidence 0.6) on the strength of the two
  fragments alone, with `-severity: [high]` and `-tags: [vuln]` inferred
  from the falsely matched templates.
- The other 9 had no template hits, so their structural hash was computed
  from an empty template set plus identical default CLI options. All 9
  collapsed to one hash, `sha256:ec2f0f3d…`, and `compare` would have
  reported them as the same actor.

## 2. What 2.0.0 changes

### 2.1 Anchoring (first candidate)

Anchoring, not length, separates the fragments above from legitimate short
tokens: `saml` in `/saml/login` and `mgmt` in `/mgmt/tm/util/bash` sit on
`/` boundaries; none of the fragments do. The first candidate build:

1. **`nucleotide/quality.py`** (new). Grades each snippet against its
   parent chunks: STRONG = anchored on both edges and ≥ 8 bytes; MEDIUM =
   anchored at any length, or unanchored and ≥ 12 bytes; WEAK = otherwise.
   Boundary set: `/?=&.:;,%+` and space.
2. **`snippets.py`**. Two-pass selection: prefer the shortest *anchored*
   unique substring; fall back to any unique substring only if no anchored
   one exists.
3. **`build.py`**. Grades every resolved snippet and writes the grade into
   the lookup.
4. **`actor.py`**. `classify_event` returns `trustworthy_templates`
   (MEDIUM or better) alongside `matched_templates`. Tool inference,
   `-severity`, and `-tags` use trustworthy hits only. A fingerprint with no
   trustworthy hits and no Nuclei UA/OAST signal is marked `low_signal`, and
   its structural hash folds in `-rate-limit`, header names, and scan
   strategy.
5. **`cli.py`**. `lookup --min-quality`; a seventh output column carrying
   the grade; `_match_score` caps at 0.5 when both fingerprints are
   `low_signal`.

Measured against the Log4Shell set, this candidate removed `//19` and
`e64/` but introduced two new false UNIQUEs: `Basic` (41 URIs, from
`landray-eis-ws-infoleak`, `/WS/Basic/Basic.asmx`, matching
`/Basic/Command/Base64/` in the JNDI path) and `6100` (11 URIs, from
`CVE-2023-40748`, `+OR+6100%3d6100%23`, matching inside hex strings). The
two actors mislabelled in 1.0.0 stayed mislabelled. That candidate was not
released; the measurements are kept in §3 as the middle column.

### 2.2 Generic tokens and match-time anchoring (release)

The release adds three rules on top of anchoring:

6. **Generic-token stop** (`quality.is_generic_token`). A snippet shorter
   than 8 bytes is split into alphanumeric segments; a segment is generic
   if it is hex-only (`6100`, `3d50`, `ffff`) or a common English word
   (`Basic`, `login`, `status`). A snippet with no non-generic segment
   cannot earn MEDIUM on anchoring, and the anchored selection pass skips
   it so the template resolves on something longer instead
   (`landray-eis-ws-infoleak`: `WS/Basic`, STRONG). The word list is
   `nucleotide/data/common-words.txt`: 28,338 alphabetic English words
   with Zipf frequency ≥ 3.0, generated from wordfreq 3.1.1 by
   `nucleotide/data/regen_common_words.py`.
7. **Percent-encoding is not a boundary.** A `%` counts as a left boundary
   only if the two characters after it are not a hex pair, so `3dASC` is
   not a token in `direction%3dASC%26`.
8. **Match-time anchoring** (`quality.match_quality`). A snippet shorter
   than 12 bytes keeps its grade for a given hit only if it is anchored in
   that URI as well; otherwise the hit counts as WEAK. Applied in both
   `lookup` and `classify_event`.

Two further changes:

9. **Low-signal discriminators** now also include the set of User-Agent
   shapes (version digits collapsed) and URI shapes (IPv4 → `A`, hex runs
   ≥ 8 → `H`, base64-like runs ≥ 16 → `B`, digit runs → `N`, truncated to
   64 characters).
10. **`--min-quality`** is available on `fingerprint` and `match` (default
    `medium`), not only on `lookup`.

## 3. Measured effect

### 3.1 Snippet selection (full corpus)

| | 1.0.0 | anchoring only | 2.0.0 |
|---|---|---|---|
| Templates resolved | 6,952 | 6,952 | 6,952 |
| Unresolved | 2,231 | 2,231 | 2,231 |
| strong / medium / weak | — | 4,254 / 2,696 / 2 | 5,303 / 1,620 / 29 |

The 29 WEAK snippets in 2.0.0 are templates whose every anchored candidate
below 8 bytes is a bare number or a common word (`/cloud/`, `/graphs`,
`:505`, …); they fell to the unanchored fallback and will not attribute.

| Template | 1.0.0 | anchoring only | 2.0.0 |
|---|---|---|---|
| httpbin-xss | `e64/` | `base64/PHNjcmlwdD5h…` (strong) | same |
| open-proxy-internal | `//19` | `/192` (medium) | `/ntp` (medium) |
| redis-config | `edis` | `redis` (medium) | same |
| filebrowser-login-panel | `on-3` | `img/icons` (strong) | same |
| wordpress-akismet | `s/ak` | `akismet` (medium) | same |
| landray-eis-ws-infoleak | `WS/B` | `Basic` (medium) | `WS/Basic` (strong) |
| CVE-2023-40748 | `%3dc` | `6100` (medium) | `6100%3d6100` (strong) |

### 3.2 Lookup on the capture sets

Log4Shell, 65 distinct URIs (58 AMBIGUOUS rows on `/favicon.ico` in every
version are omitted):

| | 1.0.0 | anchoring only | 2.0.0 | 2.0.0 `--min-quality strong` |
|---|---|---|---|---|
| UNIQUE rows | 88 | 55 | 1 | 1 |
| WEAK rows | — | 0 | 1 | 0 |
| NO_MATCH | 16 | 6 | 58 | 59 |
| Dominant snippets | `//19` ×41, `e64/` ×41 | `Basic` ×41, `6100` ×11 | `img/favicon` ×1 | `img/favicon` ×1 |

The one remaining UNIQUE is `apache-streampipes-detect` on `img/favicon`
(STRONG, anchored in the URI) for a favicon request.

galah, 62 distinct URIs (144 AMBIGUOUS rows in every version omitted):

| | 1.0.0 | anchoring only | 2.0.0 |
|---|---|---|---|
| UNIQUE rows | 37 | 23 | 18 |
| WEAK rows | — | 1 | 3 |
| NO_MATCH | 23 | 29 | 30 |

The 18 remaining 2.0.0 UNIQUE rows are on snippets such as `dns-query`,
`;stok`, `telescope`, `aws/credentials`, `geoserver/wms`, `/Autodiscover`,
`GponForm` (10 rows STRONG, 8 rows MEDIUM); the three WEAK rows are
hits that were downgraded because the snippet landed mid-token in the URI
(`eventin`, `ecp/`) or was a fallback fragment (`ovL3`). No ground truth is
available for galah, so these are reported as counts, not as true or false
positives.

### 3.3 Actor fingerprints (11 Log4Shell actors, ≥ 15 events each)

| Source IP | Events | 1.0.0 tool / hash | 2.0.0 tool / low_signal / hash | `-rate-limit` |
|---|---|---|---|---|
| 1.179.247.182 | 20 | unknown / `ec2f0f3d` | unknown / true / `c991453c` | 2.0 |
| 108.61.210.108 | 18 | unknown / `ec2f0f3d` | unknown / true / `d11fdca6` | 2.0 |
| 164.52.53.163 | 24 | unknown / `ec2f0f3d` | unknown / true / `1f08c970` | 1.0 |
| 167.71.175.10 | 38 | unknown / `ec2f0f3d` | unknown / true / `ae027bfe` | 2.0 |
| 170.210.45.163 | 19 | unknown / `ec2f0f3d` | unknown / true / `ae027bfe` | 2.0 |
| 189.188.33.125 | 17 | unknown / `ec2f0f3d` | unknown / true / `422f0484` | 1.0 |
| 195.110.6.48 | 33 | unknown / `ec2f0f3d` | unknown / true / `13809c71` | 3.0 |
| 195.54.160.149 | 116 | **nuclei 0.6** / `e4524c23` | unknown / true / `698c7706` | 2.0 |
| 23.168.193.26 | 46 | **nuclei 0.6** / `737d97ae` | unknown / true / `7e0a80d9` | 3.0 |
| 34.65.121.142 | 15 | unknown / `ec2f0f3d` | unknown / true / `1f08c970` | 1.0 |
| 86.109.208.194 | 21 | unknown / `ec2f0f3d` | unknown / true / `1f5ce162` | 1.0 |

- All 11 are now `unknown` and `low_signal`; `-severity` and `-tags` are
  empty for all of them. The intermediate candidate still had the same two
  actors at `nuclei 0.6` via `Basic`.
- 9 distinct hashes among 11 (1.0.0: 3 among 11, with 9 sharing one). The
  two pairs that still share a hash (`167.71.175.10`/`170.210.45.163`,
  `164.52.53.163`/`34.65.121.142`) have identical User-Agent shape sets and
  identical URI shape sets (`/` and `/${jndi:ldap://A:N/Exploit}`) and the
  same inferred rate limit; the fingerprint cannot tell them apart on the
  fields it records.
- No genuine Nuclei actor is present in either capture set, so there is no
  real-data positive control. Attribution from a Nuclei User-Agent is
  covered by `tests/test_regression_false_positives.py`
  (`test_genuine_nuclei_ua_still_works`).

### 3.4 Tests and coverage

| | 1.0.0 | 2.0.0 |
|---|---|---|
| Tests (`unittest discover`) | 104 passed | 137 passed |
| Line coverage, `nucleotide/*` | — | 88% |
| Line + branch coverage | — | 86% |

New: `tests/test_quality.py` (18), `tests/test_regression_false_positives.py`
(14), one in `tests/test_snippets.py`.

### 3.5 Timing (single run each, same machine, same corpus)

| Operation | 1.0.0 | anchoring only | 2.0.0 |
|---|---|---|---|
| `build`, 13,611 templates | 85.5 s | 116.1 s | 94.9 s |
| `lookup`, 65 URIs | 0.89 s | 0.56 s | 0.62 s |
| `fingerprint`, 116 events | 0.76 s | 0.81 s | 0.72 s |

Lookup and fingerprint timings are dominated by loading a 56 MB lookup
JSON; sub-second differences between single runs are noise.

## 4. Assessment

What 2.0.0 fixes, on the data available:

- Mid-token fragments are no longer selected (29 WEAK of 6,952, all
  fallbacks for templates with only generic anchored candidates).
- Short anchored common words and bare numbers no longer attribute, at
  build time (not selected) and at match time (downgraded if mid-token).
- On the Log4Shell set, false UNIQUE rows go from 88 to 1 at the default
  gate; all 11 actors are `unknown`/`low_signal` with no fabricated CLI
  options; 9 distinct hashes replace the single shared one.
- On galah, UNIQUE rows go from 37 to 18 and the surviving snippets are
  multi-byte path components rather than fragments.

What remains open:

- Anchored tokens of 4–7 bytes that are neither hex nor common English
  words (`/ntp`, `/SDK`, `m3u8`, `MyCRL`) still grade MEDIUM. Whether they
  are distinctive enough depends on the traffic; `--min-quality strong` is
  the conservative gate and is now available on `fingerprint` and `match`.
- The common-word list is English only and frequency-based; product names
  that are also common words (`telescope`, `pools`) are stopped even when
  they are the distinctive part of a path, and the template then resolves
  on a longer snippet or falls to WEAK.
- Low-signal discriminators cannot separate two actors with identical
  UA and URI shapes and rate limit; two such pairs exist in the Log4Shell
  set.
- No real-data positive control for Nuclei attribution.
- Percent-encoded input is not decoded before snippet selection; only the
  left-boundary rule in item 7 addresses it.
