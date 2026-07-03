# nucleotide user guide

## The problem

Nuclei is one of the world's most widely used vulnerability probes. Its
templates describe attack requests as YAML — which paths to hit, which
headers to inject, which callback markers to place in the payload, and
what a successful response looks like. Because the template set is
public, attackers use it too. And because a template describes both the
outgoing probe *and* the expected response, the traffic it produces is
distinctive enough that a defender who has the same YAML can recognize
it after the fact.

**nucleotide turns that idea into three concrete artifacts:**

1. **A URL-snippet lookup table.** Point-of-observation: an access log
   line. Given a URL, name the Nuclei template that most likely
   produced it.

2. **Tier-scoped detection rules.** Point-of-observation varies:
   - a plain access log sees only URLs (Tier 1);
   - a WAF sees headers and cookies too (Tier 2);
   - a network sensor with SSL keys sees request bodies (Tier 3);
   - a sensor without SSL keys sees only TLS fingerprints (Tier 4);
   - an outbound proxy or honeypot sees the response (Tier 5).

   nucleotide emits Snort/Suricata and Sigma rules for each tier so
   the right rules deploy at the right vantage point.

3. **A portable actor-behavior fingerprint.** Point-of-observation: a
   batch of events the operator has already grouped as "one actor."
   nucleotide reverse-engineers the Nuclei CLI options the actor
   must have chosen (`-tags`, `-severity`, `-H`, `-random-agent`,
   `-interactsh-server`, `-scan-strategy`, `-rate-limit`, ...), the
   template subset they favor, and any Nuclei-shaped probes that
   didn't match a known template (potential custom templates). The
   output is a YAML file the operator can `git diff` against
   fingerprints from future windows to track how the actor's
   behavior drifts over time — or share as intelligence.

nucleotide is not a SIEM, not an IDS, and not a scanner. It is a
generator of reusable artifacts.

## Install

Requires Python 3.10+ and PyYAML.

```sh
git clone https://github.com/jarocki/nucleotide
cd nucleotide
pip install -e .
```

Verify:

```sh
nucleotide --help
```

## Getting started

### 1. Build the lookup

```sh
nucleotide build \
    --templates-dir /path/to/nuclei-templates \
    --out lookup.json \
    --snort-out-dir rules/snort/ \
    --sigma-out-dir rules/sigma/
```

Or let nucleotide fetch a fresh copy of the upstream templates repo:

```sh
nucleotide build --out lookup.json \
    --snort-out-dir rules/snort/ \
    --sigma-out-dir rules/sigma/
```

The `build` command produces:

- `lookup.json` — the URL-snippet index, per-template chunks,
  fingerprints, and the full rule bundle
- `rules/snort/nuclei-t1.rules` … `nuclei-t5.rules` — one Snort/Suricata
  file per observability tier
- `rules/sigma/nuclei-t1.yml`, `nuclei-t5.yml` — Sigma rules for the two
  tiers a SIEM typically ingests (webserver access logs, proxy response
  logs)

Rule counts per tier are printed on stderr:

```
Wrote lookup.json | templates=32 snippets=26 unresolved=2 yara=31
                    snort[T1=107 T2=50 T3=3 T5=29]
```

### 2. Attribute a URL

```sh
nucleotide lookup lookup.json \
    https://victim.example/wp-content/plugins/akismet/readme.txt
```

Output is tab-separated:

```
<url>   UNIQUE|AMBIGUOUS|NO_MATCH   <template-id>   <snippet>   <severity>   <name>
```

`UNIQUE` means the URL contains a substring that only one template in
the corpus owns — a 1:1 attribution. `AMBIGUOUS` means the URL matched
a chunk shared by multiple templates. Pass `--strict` to suppress
`AMBIGUOUS`, or `--min-chunk N` to raise the shared-chunk length
threshold.

Bulk mode: pipe URLs on stdin.

```sh
awk '{print $7}' /var/log/nginx/access.log | nucleotide lookup lookup.json
```

### 3. Fingerprint an actor

The operator groups their events any way they like — by src_ip, by
JA3, by cookie jar, by campaign tag — and hands nucleotide a JSONL
file of observations:

```json
{"ts":"2026-07-02T14:00:00Z","src_ip":"1.2.3.4","target":"victim.example","uri":"/?x=${jndi:ldap://x/y}","ua":"Nuclei - Open-source project","headers":{"X-Trace-Id":"abc-1"},"body":"cb=http://x1.oast.online/probe"}
```

Only `uri` is required. Every other field enables an additional
inference:

| Field                     | Enables                              |
| ------------------------- | ------------------------------------ |
| `ts` (ISO-8601)           | `-rate-limit`, sortability           |
| `target` / `host`         | `-scan-strategy` (template/host-spray) |
| `ua` / `user_agent`       | Tool inference, `-random-agent`      |
| `headers`                 | `-H` inference (literal + shape)     |
| `cookies`                 | Same, cookie-side                    |
| `body`                    | OAST callback host discovery         |
| `oast_hosts`              | Explicit override for OAST hosts     |
| `conn_active_at_start`    | `-bulk-size` inference               |
| `resp_status`             | (reserved)                           |
| `resp_body_words`         | (reserved)                           |

Produce the fingerprint:

```sh
nucleotide fingerprint events.jsonl \
    --lookup lookup.json \
    --actor-id apt-recon-2026Q3 \
    --out actor.yml
```

The output is a single YAML file. See "Reading the fingerprint" below.

### 4. Compare two fingerprints

```sh
nucleotide compare ref-actor.yml new-actor.yml
```

Prints `identical: true` when the `structural_hash` matches; otherwise
a field-by-field diff.

### 5. Match a fresh event batch against a saved fingerprint

```sh
nucleotide match new-events.jsonl ref-actor.yml --lookup lookup.json
```

Returns a `match_score` in `[0.0, 1.0]` plus the signals that
contributed. 1.0 = same actor; below 1.0 = same actor drifting, or a
different actor with overlap.

## Reading the fingerprint

```yaml
actor_fingerprint:
  id: "apt-recon-2026Q3"
  structural_hash: "sha256:e0ff8ca61371a95fc4f63582342875f2"
  window:
    - "2026-07-02T14:00:00Z"
    - "2026-07-02T14:00:02Z"
  events_analyzed: 3

  tool_inference:
    likely_tool: "nuclei"
    confidence: 0.8
    signals:
      - "observed User-Agent matches Nuclei stock default"
      - "OAST callbacks resolve to a default interactsh host"
      - "traffic matched 3 known Nuclei template(s)"
    contradictions: []
    non_nuclei_hypothesis:
      description: "known template YAMLs consumed by a different tool"
      confidence: 0.2
      signals: []

  inferred_cli_options:
    -severity: ["critical"]
    -tags: ["cve", "rce"]
    -H:
      - name: "X-Trace-Id"
        shape: "uuid"
        value: "{uuid}"
    -random-agent: false
    -interactsh-server:
      host: "oast.online"
      is_default: true
    -rate-limit: 2.0
    -bulk-size: null
    -scan-strategy: "template-spray"

  template_preference:
    matched:
      - "CVE-2021-44228"
      - "CVE-2022-1388"
      - "CVE-2023-3519"
    hits_by_template:
      CVE-2021-44228: 12
      CVE-2022-1388: 3
      CVE-2023-3519: 1
    novel_probes: 2
    novel_probe_examples:
      - uri: "/api/experimental/probe"
        ua: "Nuclei - Open-source project"
        oast_hosts: ["custom.oast.example"]
```

Key ideas:

- **`structural_hash`** — deterministic SHA-256 over the tuple of
  `(likely_tool, cli_options, template_subset)`. Two independent
  analyses of the same actor behavior collapse to the same hash. This
  is the pivot for `compare` and `match`.

- **`confidence`** — signal-count-based (`0.5 + 0.1 * supporting -
  0.1 * contradicting`, clamped to `[0, 1]`). Deliberately simple and
  explainable. Every supporting/contradicting signal is listed
  verbatim so the operator can second-guess.

- **`inferred_cli_options`** — `null` means "indistinguishable from a
  full scan or from the tool's default." Non-null means the traffic
  narrows it down. `-H` values that vary across events are captured
  as shape templates (`{uuid}`, `{hex-32}`, `{alnum-8}`) rather than
  literal-per-event.

- **`novel_probes`** — events whose URI matched no known template but
  whose UA or OAST callback still looked Nuclei-shaped. This is the
  hook for surfacing **custom templates** the actor may have built.

## Walkthrough: two demos

Both demos are shell-script + asciicast pairs under
`docs/demos/`. Play them with `asciinema play`, or reproduce them by
running the shell script directly.

### Demo 1 — build + lookup

```sh
asciinema play docs/demos/build-and-lookup.cast
# or reproduce:
bash   docs/demos/build-and-lookup.sh
```

Walks through building a lookup + tier-scoped rule bundles, examining
one Tier 5 (response-log) rule, and looking up a URL.

### Demo 2 — actor fingerprint

```sh
asciinema play docs/demos/fingerprint-actor.cast
# or reproduce:
bash   docs/demos/fingerprint-actor.sh
```

Walks through fingerprinting three observed events, comparing a
fingerprint to itself, adding a drifted event, and scoring the drift
via `match`.

## Signature tiers, in depth

Every Snort rule and Sigma rule is tagged with the observability tier
it can be matched at. The tier appears in:

- the Snort rule's `msg:` prefix (`[T1] Nuclei ...`),
- a `metadata:tier T1;` option,
- the `--snort-out-dir` filename (`nuclei-t1.rules`),
- Sigma `tags:` (`nucleotide.tier.t1`).

**T1 — URL-log tier.** Access logs, CDN logs, DNS logs. Anchors:
`http_uri`, DNS query name, TCP request byte-sig for non-HTTP
templates.

**T2 — Header-visible tier.** WAFs, SSL-intercepting proxies. Adds
`http_user_agent`, `http_header`, `http_cookie`, plus the header
ordering signature (rebuilt from the template's declared header
order).

**T3 — Body/cleartext PCAP tier.** Decrypted or plaintext-HTTP
sensors. Adds `http_client_body` for OAST callbacks embedded in JSON
bodies, XML bodies, form-encoded bodies, plus payloads from `network:`
and `tcp:` template blocks.

**T4 — TLS-opaque PCAP tier.** Network sensors with no SSL keys.
Anchors: JA3, JA4, `alert tls; ja3.hash;`. Only emitted when a
template supplies a fully-specified `tls-config` ClientHello block.
Most templates don't.

**T5 — Response-log tier.** Outbound proxies, honeypot response
caches, forensic artifact scans. `flow:established,to_client` rules
anchored on the template's declared response `words:` and `regex:`
matchers. Catches *successful* exploitation, not just probing.

## Library use

```python
from pathlib import Path

from nucleotide import build_lookup
from nucleotide.actor import fingerprint, parse_events_jsonl, to_yaml

# Build
result = build_lookup(Path("/path/to/nuclei-templates"))

# Emit signatures per tier
from nucleotide.signatures import render_snort_by_tier
per_tier = render_snort_by_tier(result["signatures"])
Path("nuclei-t1.rules").write_text(per_tier["T1"])

# Fingerprint
events = parse_events_jsonl("events.jsonl")
fp = fingerprint(events, result, actor_id="apt-recon-2026Q3")
Path("actor.yml").write_text(to_yaml(fp))
```

## FAQ

**Does nucleotide download or run Nuclei templates?** Neither. It
reads YAML, computes signatures, and produces artifacts. It never
executes anything.

**How is this different from IDS rule packs like ET Open?** Rule packs
detect the vulnerabilities. nucleotide detects *the scanner and the
scanner's operator*. Different question.

**Why should I trust the "likely_tool: nuclei" conclusion?**
`nucleotide` shows its work. Every conclusion has a `signals` list
explaining which observables voted for it, and a `contradictions`
list of observables that voted against. If you disagree with the
weight, `_confidence()` in `nucleotide/actor.py` is 20 lines of pure
arithmetic — swap it.

**What about custom templates the actor wrote themselves?** Any event
that matches no known template but still looks Nuclei-shaped (default
UA, OAST callback to a default host) lands in
`template_preference.novel_probe_examples`. Over time, clustering
these across many actor fingerprints will surface unknown template
families — that's Phase 2.

**Can I run this against traffic in real time?** nucleotide operates on
batches, not streams. If you want streaming, run nucleotide in the
"stitched onto the end of a log pipeline" position — hand it a window
of events every 5 minutes and diff the resulting fingerprint against
the previous one.

## See also

- `README.md` — one-page overview
- `docs/demos/` — reproducible asciicast walkthroughs
- `tests/fixtures/README.md` — the 32 real Nuclei templates vendored
  for test coverage, with per-template notes on what each exercises
- `CHANGELOG.md` — release history
