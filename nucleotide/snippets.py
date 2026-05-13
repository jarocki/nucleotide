"""Compute the shortest substring of a template's URL that is unique across the corpus."""

from __future__ import annotations

from collections import defaultdict
from typing import Mapping


def compute_unique_snippets(
    corpus: Mapping[str, list[str]],
    *,
    min_len: int = 4,
    max_len: int = 80,
) -> tuple[dict[str, str], list[str]]:
    """Find each template's shortest URL substring unique across the whole corpus.

    `corpus` maps template_id -> list of literal URL chunks (placeholders already stripped).
    Returns (snippets, unresolved) where:
      - `snippets[tid]` is the chosen substring,
      - `unresolved` lists template ids that share all their substrings with another
        template (or have no chunks long enough to qualify).
    """
    candidates = {tid: [c for c in chunks if c] for tid, chunks in corpus.items()}
    resolved: dict[str, str] = {}
    unresolved = {tid for tid, ch in candidates.items() if ch}
    no_chunks = [tid for tid, ch in candidates.items() if not ch]

    for length in range(min_len, max_len + 1):
        if not unresolved:
            break

        owners: dict[str, set[str]] = defaultdict(set)
        for tid, chunks in candidates.items():
            seen: set[str] = set()
            for c in chunks:
                if len(c) < length:
                    continue
                for i in range(len(c) - length + 1):
                    seen.add(c[i : i + length])
            for s in seen:
                owners[s].add(tid)

        for tid in list(unresolved):
            chosen: str | None = None
            for c in candidates[tid]:
                if len(c) < length:
                    continue
                for i in range(len(c) - length + 1):
                    s = c[i : i + length]
                    if len(owners.get(s, ())) == 1:
                        chosen = s
                        break
                if chosen is not None:
                    break
            if chosen is not None:
                resolved[tid] = chosen
                unresolved.discard(tid)

    return resolved, sorted(unresolved | set(no_chunks))
