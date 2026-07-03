#!/usr/bin/env bash
# Reproducible source for docs/demos/build-and-lookup.cast.
# Run standalone with:
#   asciinema rec -q --cols 90 -c docs/demos/build-and-lookup.sh \
#                 docs/demos/build-and-lookup.cast
#
# This walks through: fetching a Nuclei templates tree, building a lookup
# with tier-scoped Snort and Sigma bundles, and querying a URL against it.
set -e

# Slow the demo down so a viewer can read each step.
pause() { sleep "${1:-0.6}"; }
say()   { printf "\033[1;36m$ %s\033[0m\n" "$*"; pause; eval "$@"; pause 1; }

WORK=$(mktemp -d)
cd "$WORK"

echo "# 1. Build the lookup + tier-scoped rule bundles."
echo "#    Point --templates-dir at any Nuclei templates tree; here we"
echo "#    use the 32 real templates vendored with the project."
pause 1.2

say "nucleotide build \\
      --templates-dir /home/user/nucleotide/tests/fixtures \\
      --out lookup.json \\
      --snort-out-dir rules/snort/ \\
      --sigma-out-dir rules/sigma/"

echo "# The output tells you rule counts per tier."
echo "# T1 URL log | T2 header | T3 body | T4 TLS | T5 response"
pause 1

say "ls rules/snort/ rules/sigma/"

echo "# One tier one file. Deploy each at the vantage point that sees it."
pause 1

echo "# 2. Peek at a Tier 5 (response-log) Snort rule."
say "grep -m1 'jenkins-detect' rules/snort/nuclei-t5.rules"
pause 1

echo "# 3. Query a URL against the lookup."
say "nucleotide lookup lookup.json \\
      https://victim.example/wp-content/plugins/akismet/readme.txt"
pause 1

echo "# UNIQUE means the URL contains a snippet that only one template"
echo "# in the corpus owns -- a 1:1 attribution."
pause 1.5

echo "# Done. Full output is in $WORK/"
