# Test fixtures

These four YAML files are real Nuclei templates vendored from
[projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
at commit `7c65e60871d26f26acd71b4e16aa9c8d22971ea5`. They are kept verbatim
(including the trailing `# digest:` signature lines) and are used by the
test suite only — `nucleotide` itself does not bundle any templates at
runtime; the `nucleotide build` command fetches its own copy.

| Fixture                | Upstream path                                                                                                                                            | What it exercises                                                                 |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `akismet.yaml`         | [`http/technologies/wordpress/plugins/akismet.yaml`](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/technologies/wordpress/plugins/akismet.yaml)               | HTTP `path:` block, snippet-uniqueness pair with `contact-form-7.yaml`            |
| `contact-form-7.yaml`  | [`http/technologies/wordpress/plugins/contact-form-7.yaml`](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/technologies/wordpress/plugins/contact-form-7.yaml) | HTTP `path:` block, snippet-uniqueness pair with `akismet.yaml`                   |
| `CVE-2021-44228.yaml`  | [`http/cves/2021/CVE-2021-44228.yaml`](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44228.yaml)                                          | Two `raw:` HTTP requests, ordered custom headers, `Cookie:` header, 19 `{{interactsh-url}}` OAST injection points |
| `redis-detect.yaml`    | [`network/detection/redis-detect.yaml`](https://github.com/projectdiscovery/nuclei-templates/blob/main/network/detection/redis-detect.yaml)                                         | `tcp:` network probe with no HTTP surface — exercises `network_byte_signatures` and the `no_url` path |

Upstream is licensed MIT (see
[LICENSE.md](https://github.com/projectdiscovery/nuclei-templates/blob/main/LICENSE.md)
in the templates repo). To refresh: re-download from the upstream raw URLs
and update the commit pin above + the test assertions that read these
files.
