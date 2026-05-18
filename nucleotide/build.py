"""Orchestrate fetch + parse + snippet computation + fingerprint extraction."""

from __future__ import annotations

import datetime
import subprocess
from pathlib import Path
from typing import Any

from .fingerprint import extract_fingerprints
from .parse import (
    extract_literal_chunks,
    iter_template_files,
    normalize_paths,
    parse_template,
)
from .signatures import build_signatures
from .snippets import compute_unique_snippets


def build_lookup(
    templates_dir: Path,
    *,
    source_url: str | None = None,
    min_snippet_len: int = 4,
) -> dict[str, Any]:
    templates_dir = Path(templates_dir)
    templates: dict[str, dict[str, Any]] = {}
    corpus: dict[str, list[str]] = {}

    for f in iter_template_files(templates_dir):
        doc = parse_template(f)
        if not doc:
            continue
        rel = f.relative_to(templates_dir).as_posix()
        base_id = str(doc["id"])
        tid = base_id if base_id not in templates else f"{base_id}@{rel}"
        info = doc.get("info") or {}
        paths = normalize_paths(doc)
        chunks: list[str] = []
        for p in paths:
            chunks.extend(extract_literal_chunks(p))
        templates[tid] = {
            "id": base_id,
            "name": info.get("name"),
            "severity": info.get("severity"),
            "tags": _split_tags(info.get("tags")),
            "file": rel,
            "paths": paths,
            "chunks": sorted({c for c in chunks if len(c) >= min_snippet_len}),
            "fingerprints": extract_fingerprints(doc),
        }
        corpus[tid] = chunks

    http_corpus = {tid: chunks for tid, chunks in corpus.items() if chunks}
    snippets, unresolved = compute_unique_snippets(http_corpus, min_len=min_snippet_len)
    for tid in templates:
        templates[tid]["url_snippet"] = snippets.get(tid)

    snippet_index = {snip: tid for tid, snip in snippets.items()}
    no_url_count = sum(1 for chunks in corpus.values() if not chunks)

    result = {
        "metadata": {
            "generated_utc": datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "source": source_url,
            "commit": _git_head(templates_dir),
            "template_count": len(templates),
            "http_template_count": len(http_corpus),
            "resolved_snippets": len(snippets),
            "unresolved_count": len(unresolved),
            "no_url_template_count": no_url_count,
            "min_snippet_len": min_snippet_len,
        },
        "templates": templates,
        "snippet_index": snippet_index,
        "unresolved": unresolved,
    }
    result["signatures"] = build_signatures(result)
    return result


def _split_tags(tags: Any) -> list[str]:
    if isinstance(tags, list):
        return [str(t) for t in tags]
    if isinstance(tags, str):
        return [t.strip() for t in tags.split(",") if t.strip()]
    return []


def _git_head(d: Path) -> str | None:
    try:
        r = subprocess.run(
            ["git", "-C", str(d), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return r.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
