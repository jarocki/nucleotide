"""Walk a directory of Nuclei templates and extract URL paths + literal chunks."""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any, Iterator

import yaml

logger = logging.getLogger(__name__)

PLACEHOLDER_RE = re.compile(r"\{\{[^}]*\}\}")
SKIP_DIRS = {".git", ".github", "node_modules", ".venv", "__pycache__"}
MAX_TEMPLATE_SIZE = 10 * 1024 * 1024  # 10 MB per template


def iter_template_files(root: Path) -> Iterator[Path]:
    """Safely iterate template files with path traversal protection.
    
    Args:
        root: Root directory to search
        
    Yields:
        Path objects for .yaml/.yml template files
        
    Raises:
        ValueError: If root doesn't exist or isn't a directory
    """
    root = Path(root)
    if not root.exists():
        raise ValueError(f"Template directory does not exist: {root}")
    if not root.is_dir():
        raise ValueError(f"Template path is not a directory: {root}")
    
    for dirpath, dirnames, filenames in os.walk(root):
        # Prevent directory traversal
        dirnames[:] = [
            d for d in dirnames 
            if d not in SKIP_DIRS 
            and not d.startswith(".")
            and not os.path.islink(os.path.join(dirpath, d))
        ]
        
        for fn in filenames:
            if fn.endswith((".yaml", ".yml")):
                path = Path(dirpath) / fn
                # Verify path is within root to prevent symlink attacks
                try:
                    path.relative_to(root)
                    yield path
                except ValueError:
                    logger.warning(f"Skipping file outside root: {path}")


def parse_template(path: Path) -> dict[str, Any] | None:
    """Safely parse a YAML template with validation.
    
    Args:
        path: Path to template file
        
    Returns:
        Parsed template dict or None if invalid
    """
    try:
        # Check file size before loading
        file_size = path.stat().st_size
        if file_size > MAX_TEMPLATE_SIZE:
            logger.warning(f"Template exceeds size limit: {path} ({file_size} bytes)")
            return None
        
        with path.open("rb") as f:
            doc = yaml.safe_load(f)
    except yaml.YAMLError as e:
        logger.debug(f"YAML parse error in {path}: {e}")
        return None
    except (OSError, UnicodeDecodeError) as e:
        logger.debug(f"File read error in {path}: {e}")
        return None
    
    if not isinstance(doc, dict):
        logger.debug(f"Template is not a dict: {path}")
        return None
    
    if "id" not in doc or "info" not in doc:
        logger.debug(f"Template missing required fields: {path}")
        return None
    
    # Validate id is a string
    if not isinstance(doc.get("id"), str):
        logger.debug(f"Template id is not a string: {path}")
        return None
    
    return doc


def _path_from_raw(raw: str) -> str | None:
    """Pull the request-target out of the first line of a raw HTTP request.

    Only accepts targets that look like a real request-target: an origin-form
    path (`/...`), an absolute-form URL, or `*` (OPTIONS *). This filters out
    templates with malformed request lines whose `parts[1]` would otherwise
    be misread as a path (e.g., a literal `HTTP/1.1`).
    
    Args:
        raw: Raw HTTP request string
        
    Returns:
        Extracted request target or None if invalid
    """
    if not isinstance(raw, str) or not raw.strip():
        return None
    
    first = raw.lstrip().splitlines()[0] if raw.strip() else ""
    parts = first.split()
    
    if len(parts) < 2:
        return None
    
    method = parts[0]
    target = parts[1]
    
    # Validate HTTP method is uppercase alphanumeric
    if not method.isupper() or not method.replace("-", "").isalpha():
        return None
    
    # Accept valid request targets
    if target == "*" or target.startswith(("/", "http://", "https://")):
        return target
    
    return None


def normalize_paths(template: dict) -> list[str]:
    """Extract HTTP paths from a template.
    
    Args:
        template: Parsed template dictionary
        
    Returns:
        List of normalized path strings
    """
    paths: list[str] = []
    
    for key in ("http", "requests"):
        block = template.get(key)
        if not isinstance(block, list):
            continue
        
        for req in block:
            if not isinstance(req, dict):
                continue
            
            for p in req.get("path") or []:
                if isinstance(p, str) and p:
                    paths.append(p)
            
            for raw in req.get("raw") or []:
                if isinstance(raw, str):
                    p = _path_from_raw(raw)
                    if p:
                        paths.append(p)
    
    return paths


def extract_literal_chunks(path: str) -> list[str]:
    """Strip Nuclei placeholder expressions and return the literal substrings.
    
    Args:
        path: Path possibly containing {{...}} placeholders
        
    Returns:
        List of literal substrings (placeholders removed)
    """
    if not isinstance(path, str):
        return []
    
    return [c for c in PLACEHOLDER_RE.split(path) if c]
