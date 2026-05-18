"""Command-line entry point: build the lookup, query it against URLs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .build import build_lookup
from .fetch import PROJECTDISCOVERY_REPO, fetch
from .signatures import render_snort, render_yara


def _build(args: argparse.Namespace) -> int:
    if args.templates_dir:
        tdir = args.templates_dir
        source = str(tdir.resolve())
    else:
        tdir = fetch(args.repo, args.cache_dir, update=not args.no_fetch)
        source = args.repo
    result = build_lookup(tdir, source_url=source, min_snippet_len=args.min_len)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True))
    if args.yara_out:
        args.yara_out.write_text(render_yara(result.get("signatures") or {}))
    if args.snort_out:
        args.snort_out.write_text(render_snort(result.get("signatures") or {}))
    md = result["metadata"]
    sigs = result.get("signatures") or {}
    yara_n = len(sigs.get("yara") or {})
    snort_n = sum(len(v) for v in (sigs.get("snort") or {}).values())
    print(
        f"Wrote {args.out} | templates={md['template_count']} "
        f"snippets={md['resolved_snippets']} unresolved={md['unresolved_count']} "
        f"yara={yara_n} snort={snort_n}",
        file=sys.stderr,
    )
    return 0


def _lookup(args: argparse.Namespace) -> int:
    data = json.loads(args.lookup_file.read_text())
    snippet_index: dict[str, str] = data.get("snippet_index", {})
    snippet_items = sorted(snippet_index.items(), key=lambda kv: -len(kv[0]))
    templates: dict[str, dict] = data.get("templates", {})

    chunk_targets: list[tuple[str, str]] = []
    if not args.strict:
        seen_pairs: set[tuple[str, str]] = set()
        for tid, meta in templates.items():
            if meta.get("url_snippet"):
                continue
            for c in meta.get("chunks") or ():
                if len(c) >= args.min_chunk and (c, tid) not in seen_pairs:
                    chunk_targets.append((c, tid))
                    seen_pairs.add((c, tid))
        chunk_targets.sort(key=lambda kv: -len(kv[0]))

    queries = args.query
    if not queries and not sys.stdin.isatty():
        queries = [line.rstrip("\n") for line in sys.stdin if line.strip()]

    for q in queries:
        printed_any = False
        for snip, tid in snippet_items:
            if snip in q:
                meta = templates.get(tid, {})
                print(
                    f"{q}\tUNIQUE\t{tid}\t{snip}\t{meta.get('severity','')}\t{meta.get('name','')}"
                )
                printed_any = True
        for chunk, tid in chunk_targets:
            if chunk in q:
                meta = templates.get(tid, {})
                print(
                    f"{q}\tAMBIGUOUS\t{tid}\t{chunk}\t{meta.get('severity','')}\t{meta.get('name','')}"
                )
                printed_any = True
        if not printed_any:
            print(f"{q}\tNO_MATCH")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="nucleotide",
        description="Build a URL-snippet lookup table mapping observed URLs back to Nuclei templates.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    bld = sub.add_parser("build", help="Fetch templates and build the lookup table.")
    bld.add_argument("--repo", default=PROJECTDISCOVERY_REPO, help="Template repo URL.")
    bld.add_argument(
        "--templates-dir",
        type=Path,
        default=None,
        help="Use an existing local template tree instead of fetching.",
    )
    bld.add_argument(
        "--cache-dir",
        type=Path,
        default=Path.home() / ".cache" / "nucleotide" / "templates",
        help="Where to clone templates if --templates-dir is not set.",
    )
    bld.add_argument("--out", type=Path, default=Path("nucleotide-lookup.json"))
    bld.add_argument(
        "--min-len",
        type=int,
        default=4,
        help="Minimum snippet length. Increase (e.g. 6 or 8) for higher precision against arbitrary log traffic.",
    )
    bld.add_argument(
        "--no-fetch",
        action="store_true",
        help="Reuse the cache directory without pulling updates.",
    )
    bld.add_argument(
        "--yara-out",
        type=Path,
        default=None,
        help="Also write per-template YARA rules to this path.",
    )
    bld.add_argument(
        "--snort-out",
        type=Path,
        default=None,
        help="Also write per-template Snort/Suricata rules to this path.",
    )
    bld.set_defaults(func=_build)

    look = sub.add_parser(
        "lookup", help="Match URLs (args or stdin) against a built lookup file."
    )
    look.add_argument("lookup_file", type=Path)
    look.add_argument("query", nargs="*")
    look.add_argument(
        "--strict",
        action="store_true",
        help="Only report 1:1 unique-snippet matches; suppress shared-path (AMBIGUOUS) hits.",
    )
    look.add_argument(
        "--min-chunk",
        type=int,
        default=8,
        help="Minimum length for shared-path chunks considered in AMBIGUOUS lookup (default 8).",
    )
    look.set_defaults(func=_lookup)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
