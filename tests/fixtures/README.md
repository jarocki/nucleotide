# Test fixtures

These YAML files are real Nuclei templates vendored from
[projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
at commit `7c65e60871d26f26acd71b4e16aa9c8d22971ea5`. They are kept verbatim
(including the trailing `# digest:` signature lines) and are used by the
test suite only — `nucleotide` itself does not bundle any templates at
runtime; the `nucleotide build` command fetches its own copy.

The fixture set was deliberately picked to stress the fingerprint and
signature-generation code along orthogonal axes: HTTP `path:` snippet
collisions, raw HTTP requests, ordered custom headers, payload-bearing
header values (Struts2 OGNL, Log4j JNDI, Shellshock bash), `Cookie:`
parsing both well-formed and weaponized, OAST callback markers,
response-side matchers (`words:` / `regex:`), TCP byte signatures, and
DNS / SSL probes that have no HTTP surface at all.

| Fixture                          | Upstream path                                                                                                                                                                            | What it exercises                                                                                                       |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `akismet.yaml`                   | `http/technologies/wordpress/plugins/akismet.yaml`                                                                                                                                       | HTTP `path:` block; one of four WordPress plugins sharing the `/wp-content/plugins/` prefix                              |
| `contact-form-7.yaml`            | `http/technologies/wordpress/plugins/contact-form-7.yaml`                                                                                                                                | Same shape as `akismet.yaml` — snippet-uniqueness pair                                                                  |
| `elementor.yaml`                 | `http/technologies/wordpress/plugins/elementor.yaml`                                                                                                                                     | Third WP plugin in the snippet-uniqueness pool                                                                          |
| `jetpack.yaml`                   | `http/technologies/wordpress/plugins/jetpack.yaml`                                                                                                                                       | Fourth WP plugin — pushes the unique-snippet algorithm to differentiate four templates sharing the same path prefix     |
| `CVE-2021-44228.yaml`            | `http/cves/2021/CVE-2021-44228.yaml` (Log4Shell)                                                                                                                                         | Two `raw:` HTTP requests, ~17 ordered headers, `Cookie:` header, 19+ `{{interactsh-url}}` OAST injection points          |
| `CVE-2017-5638.yaml`             | `http/cves/2017/CVE-2017-5638.yaml` (Struts2 OGNL)                                                                                                                                       | Single raw request with a giant OGNL `Content-Type` payload — exercises the "payload-like value" filter on a header     |
| `CVE-2014-6271.yaml`             | `http/cves/2014/CVE-2014-6271.yaml` (Shellshock)                                                                                                                                         | Bash payload in `User-Agent`/`Referer`/`Cookie` headers — exercises cookie-validation fallback to opaque mode            |
| `CVE-2022-22965.yaml`            | `http/cves/2022/CVE-2022-22965.yaml` (Spring4Shell)                                                                                                                                       | Two raw requests, OAST in body + query string, `Content-Type: application/x-www-form-urlencoded` body                    |
| `CVE-2022-1388.yaml`             | `http/cves/2022/CVE-2022-1388.yaml` (F5 BIG-IP iControl REST)                                                                                                                            | Many auth-bypass headers (`X-F5-Auth-Token`, `Authorization`, `X-Forwarded-For`, etc.)                                   |
| `CVE-2019-19781.yaml`            | `http/cves/2019/CVE-2019-19781.yaml` (Citrix path traversal)                                                                                                                             | Distinctive path traversal URI literal                                                                                  |
| `CVE-2021-26084.yaml`            | `http/cves/2021/CVE-2021-26084.yaml` (Confluence OGNL)                                                                                                                                   | Body-side OGNL payload                                                                                                  |
| `git-config.yaml`                | `http/exposures/configs/git-config.yaml`                                                                                                                                                 | Exposed-file probe with response-side `word:` matcher (`[core]`)                                                        |
| `jenkins-detect.yaml`            | `http/technologies/jenkins-detect.yaml`                                                                                                                                                  | Multiple paths + response `word:` matchers (`x-jenkins:`, `Jenkins`) — exercises response-side anchors                  |
| `redis-detect.yaml`              | `network/detection/redis-detect.yaml`                                                                                                                                                    | `tcp:` block (no HTTP surface) — exercises `network_byte_signatures` and `no_url_template_count`                         |
| `azure-takeover-detection.yaml`  | `dns/azure-takeover-detection.yaml`                                                                                                                                                       | DNS-only template — exercises `dns_queries` / `dns_record_types` and YARA-only response anchors                          |
| `expired-ssl.yaml`               | `ssl/expired-ssl.yaml`                                                                                                                                                                   | `ssl:` block with only a DSL matcher — verifies the build still completes when a template yields no concrete byte anchors |

Upstream is licensed MIT (see
[LICENSE.md](https://github.com/projectdiscovery/nuclei-templates/blob/main/LICENSE.md)
in the templates repo). To refresh: re-download from the upstream raw URLs
and update the commit pin above + the test assertions that read these
files.
