"""Walk a directory of Nuclei templates and extract URL paths + literal chunks."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterator

import yaml

PLACEHOLDER_RE = re.compile(r"\{\{[^}]*\}\}")
SKIP_DIRS = {".git", ".github", "node_modules", ".venv", "__pycache__"}


def iter_template_files(root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            if fn.endswith((".yaml", ".yml")):
                yield Path(dirpath) / fn


def parse_template(path: Path) -> dict | None:
    try:
        with path.open("rb") as f:
            doc = yaml.safe_load(f)
    except (yaml.YAMLError, OSError, UnicodeDecodeError):
        return None
    if not isinstance(doc, dict) or "id" not in doc or "info" not in doc:
        return None
    return doc


def _path_from_raw(raw: str) -> str | None:
    """Pull the request-target out of the first line of a raw HTTP request.

    Only accepts targets that look like a real request-target: an origin-form
    path (`/...`), an absolute-form URL, or `*` (OPTIONS *). This filters out
    templates with malformed request lines whose `parts[1]` would otherwise
    be misread as a path (e.g., a literal `HTTP/1.1`).
    """
    first = raw.lstrip().splitlines()[0] if raw.strip() else ""
    parts = first.split()
    if len(parts) < 2 or not parts[0].isupper():
        return None
    target = parts[1]
    if target == "*" or target.startswith(("/", "http://", "https://")):
        return target
    return None


def normalize_paths(template: dict) -> list[str]:
    paths: list[str] = []
    for key in ("http", "requests"):
        block = template.get(key)
        if not isinstance(block, list):
            continue
        for req in block:
            if not isinstance(req, dict):
                continue
            for p in req.get("path") or []:
                if isinstance(p, str):
                    paths.append(p)
            for raw in req.get("raw") or []:
                if isinstance(raw, str):
                    p = _path_from_raw(raw)
                    if p:
                        paths.append(p)
    return paths


def extract_literal_chunks(path: str) -> list[str]:
    """Strip Nuclei placeholder expressions and return the literal substrings."""
    return [c for c in PLACEHOLDER_RE.split(path) if c]
