"""Parse Nuclei payloads: raw HTTP requests, cookies, OAST injection points.

The fingerprint module pulls from this to capture *what the template actually
asks the client to send* (header ordering, cookies, the literal context around
each OAST callback marker), as opposed to just hashing whole blobs.
"""

from __future__ import annotations

import re
from typing import Any

# Built-in Nuclei interactsh placeholders, plus the looser `oast-*` family some
# templates use. We deliberately do NOT match generic `{{...}}` here -- that
# lives in parse.PLACEHOLDER_RE and is used for path normalization, not OAST.
OAST_TOKEN_RE = re.compile(
    r"\{\{\s*(interactsh-[A-Za-z0-9_-]+|interactsh|oast(?:-[A-Za-z0-9_-]+)?)\s*\}\}"
)
COOKIE_HEADER_RE = re.compile(r"^cookie$", re.IGNORECASE)


def parse_raw_request(raw: str) -> dict[str, Any]:
    """Parse a Nuclei raw HTTP request block into method/target/headers/body.

    Header order (including duplicate names) is preserved exactly as written.
    Returns an empty dict if the first line doesn't look like a request line.
    """
    text = raw.lstrip("\n")
    lines = text.splitlines()
    if not lines:
        return {}
    parts = lines[0].split()
    if len(parts) < 2 or not parts[0].isupper():
        return {}
    headers: list[tuple[str, str]] = []
    body_lines: list[str] = []
    in_body = False
    for line in lines[1:]:
        if not in_body:
            if line == "":
                in_body = True
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                headers.append((k.strip(), v.lstrip()))
        else:
            body_lines.append(line)
    return {
        "method": parts[0],
        "target": parts[1],
        "headers": headers,
        "body": "\n".join(body_lines),
    }


def parse_cookie_header(value: str) -> list[tuple[str, str]]:
    """Split a Cookie header value into [(name, value), ...].

    Cookies without `=` are kept as (name, "") so that bare flags survive.
    """
    cookies: list[tuple[str, str]] = []
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            n, v = part.split("=", 1)
            cookies.append((n.strip(), v.strip()))
        else:
            cookies.append((part, ""))
    return cookies


def find_oast_injections(
    text: str,
    location: str,
    *,
    context: int = 24,
) -> list[dict[str, str]]:
    """Locate OAST callback placeholders in `text` with `context` bytes of surrounding literal.

    Returns a list of dicts with `location`, `placeholder`, `before`, `after`.
    The before/after slices are the immediate literal context (other template
    placeholders are *not* stripped) -- they're meant to be used as anchor
    strings for IDS signatures.
    """
    out: list[dict[str, str]] = []
    for m in OAST_TOKEN_RE.finditer(text):
        s, e = m.span()
        out.append(
            {
                "location": location,
                "placeholder": m.group(0),
                "before": text[max(0, s - context) : s],
                "after": text[e : e + context],
            }
        )
    return out
