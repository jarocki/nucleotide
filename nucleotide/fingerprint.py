"""Extract per-template fingerprints (UA, header/body hashes, network byte sigs, TLS hints).

Honest scope note on JA3/JA4: those describe a TLS client's ClientHello, which is a
property of Nuclei's HTTP client at runtime, not of the YAML template. We therefore
compute them only when a template carries enough explicit TLS configuration to nail
down a ClientHello, and otherwise expose `tls_hints` and a `request_shape` digest
that play the same fingerprinting role for the layer the template *does* control.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

UA_HEADER_RE = re.compile(r"(?i)^user-agent$")


def _sha(b: bytes, length: int = 16) -> str:
    return hashlib.sha256(b).hexdigest()[:length]


def _md5(b: bytes) -> str:
    return hashlib.md5(b, usedforsecurity=False).hexdigest()


def _iter_http_requests(template: dict):
    for key in ("http", "requests"):
        block = template.get(key)
        if isinstance(block, list):
            for req in block:
                if isinstance(req, dict):
                    yield req


def _iter_network_blocks(template: dict):
    for key in ("network", "tcp"):
        block = template.get(key)
        if isinstance(block, list):
            for n in block:
                if isinstance(n, dict):
                    yield n


def _maybe_ja3(template: dict) -> str | None:
    """Build a JA3 hash only when the template fully specifies a ClientHello.

    JA3 = MD5("SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats")
    Nuclei templates almost never carry that level of detail; this returns None for
    typical templates and gives a real value for the rare TLS-tuned probe.
    """
    tls = template.get("tls-config") or template.get("tls_config")
    if not isinstance(tls, dict):
        return None
    needed = ("version", "ciphers", "extensions", "curves", "ec_point_formats")
    if not all(k in tls for k in needed):
        return None
    parts = [
        str(tls["version"]),
        "-".join(str(x) for x in tls["ciphers"]),
        "-".join(str(x) for x in tls["extensions"]),
        "-".join(str(x) for x in tls["curves"]),
        "-".join(str(x) for x in tls["ec_point_formats"]),
    ]
    return _md5(",".join(parts).encode())


def _maybe_ja4(template: dict) -> str | None:
    """JA4 = `<proto><tlsver><sni><nciph><next><alpn>_<cipherhash>_<exthash>`.

    Same caveat as JA3: only emitted for templates that carry the inputs.
    """
    tls = template.get("ja4") or template.get("tls-config") or template.get("tls_config")
    if not isinstance(tls, dict):
        return None
    needed = ("version", "ciphers", "extensions", "alpn")
    if not all(k in tls for k in needed):
        return None
    proto = "t"
    ver_map = {"1.0": "10", "1.1": "11", "1.2": "12", "1.3": "13"}
    tlsver = ver_map.get(str(tls["version"]), "00")
    sni = "d" if tls.get("sni", True) else "i"
    ciphers = sorted(str(x) for x in tls["ciphers"])
    exts = sorted(str(x) for x in tls["extensions"])
    nciph = f"{len(ciphers):02d}"
    next_ = f"{len(exts):02d}"
    alpn = (str(tls["alpn"]) + "00")[:2]
    a = f"{proto}{tlsver}{sni}{nciph}{next_}{alpn}"
    b = hashlib.sha256(",".join(ciphers).encode()).hexdigest()[:12]
    c = hashlib.sha256(",".join(exts).encode()).hexdigest()[:12]
    return f"{a}_{b}_{c}"


def extract_fingerprints(template: dict) -> dict[str, Any]:
    fp: dict[str, Any] = {}
    user_agents: set[str] = set()
    custom_headers: list[tuple[str, str]] = []
    bodies: list[str] = []
    raws: list[str] = []
    methods: set[str] = set()

    for req in _iter_http_requests(template):
        m = req.get("method")
        if isinstance(m, str):
            methods.add(m.upper())
        headers = req.get("headers") or {}
        if isinstance(headers, dict):
            for hk, hv in headers.items():
                if not isinstance(hk, str):
                    continue
                value = "" if hv is None else str(hv)
                if UA_HEADER_RE.match(hk):
                    if value.strip():
                        user_agents.add(value.strip())
                custom_headers.append((hk, value))
        body = req.get("body")
        if isinstance(body, str) and body:
            bodies.append(body)
        for raw in req.get("raw") or []:
            if isinstance(raw, str):
                raws.append(raw)

    byte_sigs: list[str] = []
    for n in _iter_network_blocks(template):
        for inp in n.get("inputs") or []:
            if not isinstance(inp, dict):
                continue
            data = inp.get("data")
            if not isinstance(data, str):
                continue
            if inp.get("type") == "hex":
                byte_sigs.append("hex:" + re.sub(r"\s+", "", data).lower())
            else:
                byte_sigs.append(f"str:{_sha(data.encode())}")

    tls_hints: dict[str, Any] = {}
    ssl_block = template.get("ssl") or []
    if isinstance(ssl_block, list):
        ciphers, versions = set(), set()
        for s in ssl_block:
            if not isinstance(s, dict):
                continue
            for c in s.get("cipher_suites") or []:
                ciphers.add(c)
            for k in ("min_version", "max_version", "tls_version"):
                v = s.get(k)
                if v:
                    versions.add(str(v))
        if ciphers:
            tls_hints["cipher_suites"] = sorted(map(str, ciphers))
        if versions:
            tls_hints["versions"] = sorted(versions)

    if user_agents:
        fp["user_agents"] = sorted(user_agents)
    if custom_headers:
        canon = "\n".join(f"{k.lower()}:{v}" for k, v in sorted(custom_headers))
        fp["header_signature"] = f"sha256:{_sha(canon.encode())}"
        fp["header_names"] = sorted({k.lower() for k, _ in custom_headers})
    if bodies:
        fp["body_signatures"] = [f"sha256:{_sha(b.encode())}" for b in bodies]
    if raws:
        fp["raw_request_signatures"] = [f"sha256:{_sha(r.encode())}" for r in raws]
    if byte_sigs:
        fp["network_byte_signatures"] = byte_sigs
    if tls_hints:
        fp["tls_hints"] = tls_hints
    if methods:
        fp["http_methods"] = sorted(methods)

    if methods or custom_headers or bodies or raws:
        canon_parts: list[str] = list(sorted(methods))
        canon_parts.extend(f"H:{k.lower()}:{v}" for k, v in sorted(custom_headers))
        canon_parts.extend(f"B:{_sha(b.encode())}" for b in bodies)
        canon_parts.extend(f"R:{_sha(r.encode())}" for r in raws)
        fp["request_shape"] = f"sha256:{_sha('|'.join(canon_parts).encode())}"

    ja3 = _maybe_ja3(template)
    if ja3:
        fp["ja3"] = ja3
    ja4 = _maybe_ja4(template)
    if ja4:
        fp["ja4"] = ja4

    return fp
