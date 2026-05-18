"""Generate YARA and Snort/Suricata signatures from extracted Nuclei fingerprints.

The strings we emit come straight from the fingerprint dict that
`extract_fingerprints` produced: unique URL snippet, User-Agent values, custom
header names+values (in original send order), cookie names, and the literal
context around any OAST callback marker. We deliberately skip header *values*
that still carry `{{...}}` placeholders -- Nuclei will fill those in at
runtime, so they aren't useful as static byte signatures.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Iterable

_YARA_NAME_RE = re.compile(r"[^A-Za-z0-9_]")

# Headers we won't pivot on -- they're either supplied by every HTTP client or
# tend to mutate per environment (Host, content negotiation).
_GENERIC_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "content-type",
        "accept",
        "accept-encoding",
        "accept-language",
        "connection",
    }
)


def _yara_name(tid: str) -> str:
    name = _YARA_NAME_RE.sub("_", tid)
    if not name or not (name[0].isalpha() or name[0] == "_"):
        name = "_" + name
    return f"nuclei_{name}"


def _yara_escape(s: str) -> str:
    # YARA double-quoted strings honor: \" \\ \t \n \r \x##
    out: list[str] = []
    for ch in s:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20 or o > 0x7E:
            # Encode any non-printable byte explicitly. For multi-byte UTF-8
            # we hex-encode each byte separately so the rule matches the wire
            # bytes, not a Python string abstraction.
            for b in ch.encode("utf-8"):
                out.append(f"\\x{b:02x}")
        else:
            out.append(ch)
    return "".join(out)


def _snort_escape(s: str) -> str:
    """Encode a string as a Snort `content:` payload.

    Printable ASCII goes through verbatim, with the four content-grammar
    reserved chars (`"`, `;`, `\\`, `|`) lifted into a `|hex|` block alongside
    every non-ASCII / control byte. Multi-byte UTF-8 is preserved byte-wise.
    """
    out: list[str] = []
    hex_run: list[str] = []

    def flush_hex() -> None:
        if hex_run:
            out.append("|" + " ".join(hex_run) + "|")
            hex_run.clear()

    for ch in s:
        b = ch.encode("utf-8")
        if len(b) == 1 and 0x20 <= b[0] <= 0x7E and ch not in ('"', ";", "\\", "|"):
            flush_hex()
            out.append(ch)
        else:
            for byte in b:
                hex_run.append(f"{byte:02X}")
    flush_hex()
    return "".join(out)


def _stable_sid(tid: str, salt: int = 0) -> int:
    """Deterministically pick a SID in the 1_000_000..1_899_999 range."""
    h = hashlib.sha256(f"{tid}:{salt}".encode()).digest()
    return 1_000_000 + int.from_bytes(h[:4], "big") % 900_000


def _interesting_headers(header_order: Iterable[Any]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for kv in header_order or []:
        if not isinstance(kv, (list, tuple)) or len(kv) != 2:
            continue
        k, v = kv
        if not isinstance(k, str) or not isinstance(v, str):
            continue
        if k.lower() in _GENERIC_HEADERS or k.lower() == "user-agent":
            continue
        if not v.strip() or "{{" in v:
            continue
        pair = (k, v)
        if pair in seen:
            continue
        seen.add(pair)
        out.append(pair)
    return out


def yara_rule_for(tid: str, t: dict[str, Any]) -> str | None:
    """Build a single YARA rule for one template, or None if no signal is usable.

    The condition is `any of them` -- each clause is independently sufficient
    to flag the request. Callers wanting stricter behavior can post-process
    the emitted rule.
    """
    fp = t.get("fingerprints") or {}
    strings: list[tuple[str, str]] = []
    used_values: set[str] = set()

    def add(prefix: str, value: str) -> None:
        if not value or value in used_values:
            return
        used_values.add(value)
        strings.append((f"${prefix}_{len(strings)}", value))

    snip = t.get("url_snippet")
    if isinstance(snip, str) and len(snip) >= 6:
        add("path", snip)

    for ua in fp.get("user_agents") or []:
        if isinstance(ua, str) and ua.strip():
            add("ua", f"User-Agent: {ua}")

    for k, v in _interesting_headers(fp.get("header_order")):
        add("hdr", f"{k}: {v}")

    for ck in fp.get("cookie_names") or []:
        if isinstance(ck, str) and ck.strip():
            add("ck", f"{ck}=")

    for o in fp.get("oast_injections") or []:
        if not isinstance(o, dict):
            continue
        before = (o.get("before") or "").rstrip()
        after = (o.get("after") or "").lstrip()
        if len(before) >= 4 and "{{" not in before:
            add("oast_pre", before)
        if len(after) >= 4 and "{{" not in after:
            add("oast_post", after)

    if not strings:
        return None

    lines: list[str] = []
    lines.append(f"rule {_yara_name(tid)}")
    lines.append("{")
    lines.append("    meta:")
    lines.append(f'        nuclei_id = "{_yara_escape(tid)}"')
    if t.get("severity"):
        lines.append(f'        severity = "{_yara_escape(str(t["severity"]))}"')
    if t.get("name"):
        lines.append(f'        nuclei_name = "{_yara_escape(str(t["name"]))}"')
    lines.append("    strings:")
    for label, value in strings:
        lines.append(f'        {label} = "{_yara_escape(value)}"')
    lines.append("    condition:")
    lines.append("        any of them")
    lines.append("}")
    return "\n".join(lines) + "\n"


def snort_rules_for(tid: str, t: dict[str, Any]) -> list[str]:
    """Emit a list of Snort 3 / Suricata rules for one template.

    Rules use sticky-buffer-less classic Snort 2 syntax (`content:"..."; http_uri;`)
    which Suricata also understands. SIDs are deterministic per (tid, salt) so
    re-running the build doesn't churn rule IDs.
    """
    fp = t.get("fingerprints") or {}
    rules: list[str] = []
    salt = 0
    msg_base = f"Nuclei {tid}".replace('"', "'")

    def emit(content: str, buffer: str | None, suffix: str, *, nocase: bool = False) -> None:
        nonlocal salt
        sid = _stable_sid(tid, salt)
        salt += 1
        opts = [
            f'msg:"{msg_base} ({suffix})"',
            "flow:established,to_server",
            f'content:"{content}"',
        ]
        if buffer:
            opts.append(buffer)
        if nocase:
            opts.append("nocase")
        opts.append(f"sid:{sid}")
        opts.append("rev:1")
        opts.append("classtype:web-application-activity")
        rules.append(
            "alert http any any -> any any (" + "; ".join(opts) + ";)"
        )

    snip = t.get("url_snippet")
    if isinstance(snip, str) and len(snip) >= 4:
        emit(_snort_escape(snip), "http_uri", "URI snippet", nocase=True)

    for ua in fp.get("user_agents") or []:
        if isinstance(ua, str) and ua.strip():
            emit(_snort_escape(ua), "http_user_agent", "User-Agent")

    for k, v in _interesting_headers(fp.get("header_order")):
        emit(_snort_escape(f"{k}: {v}"), "http_header", f"header {k}")

    for ck in fp.get("cookie_names") or []:
        if isinstance(ck, str) and ck.strip():
            emit(_snort_escape(f"{ck}="), "http_cookie", f"cookie {ck}")

    for o in fp.get("oast_injections") or []:
        if not isinstance(o, dict):
            continue
        before = (o.get("before") or "").rstrip()
        after = (o.get("after") or "").lstrip()
        loc = o.get("location") or ""
        buffer = "http_client_body" if "body" in loc else None
        if len(before) >= 6 and "{{" not in before:
            emit(_snort_escape(before), buffer, f"OAST pre @ {loc}")
        if len(after) >= 6 and "{{" not in after:
            emit(_snort_escape(after), buffer, f"OAST post @ {loc}")

    return rules


def build_signatures(lookup: dict[str, Any]) -> dict[str, Any]:
    """Compute YARA + Snort rule sets for every template in a built lookup."""
    yara_rules: dict[str, str] = {}
    snort_rules: dict[str, list[str]] = {}
    for tid, t in (lookup.get("templates") or {}).items():
        y = yara_rule_for(tid, t)
        if y:
            yara_rules[tid] = y
        s = snort_rules_for(tid, t)
        if s:
            snort_rules[tid] = s
    return {"yara": yara_rules, "snort": snort_rules}


def render_yara(signatures: dict[str, Any]) -> str:
    """Concatenate every YARA rule in the bundle into a single file-ready string."""
    rules = (signatures or {}).get("yara") or {}
    return "\n".join(rules[tid] for tid in sorted(rules))


def render_snort(signatures: dict[str, Any]) -> str:
    """Flatten every Snort rule in the bundle into a newline-terminated string."""
    rules = (signatures or {}).get("snort") or {}
    out: list[str] = []
    for tid in sorted(rules):
        out.extend(rules[tid])
    return "\n".join(out) + ("\n" if out else "")
