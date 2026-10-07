"""Minimal offline DKIM signer used only to mint test fixtures.

It deliberately shares the production canonicalization code (``dkim_core``)
but performs the *private* RSA operation itself so fixture generation needs no
network access.  Generated fixtures are additionally cross-checked against the
OpenSSL CLI at generation time, and the frozen .eml files are what the CI /
verify container consumes (so the runtime image needs no private key and no
openssl binary).
"""

from __future__ import annotations

import base64
import hashlib
import os
import sys
from typing import Dict, List, Optional, Tuple

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "app"))
)

import dkim_core  # noqa: E402

_DIGEST_INFO_SHA256 = dkim_core._DIGEST_INFO_PREFIX["sha256"]


# --------------------------------------------------------------------------
# PKCS#8 / PKCS#1 private key parsing (test tool only)
# --------------------------------------------------------------------------

def _read_tlv_all(data: bytes, offset: int = 0) -> List[Tuple[int, bytes]]:
    out: List[Tuple[int, bytes]] = []
    pos = offset
    while pos < len(data):
        tag, value, pos = dkim_core._read_tlv(data, pos)
        out.append((tag, value))
    return out


def load_rsa_private_key(path: str) -> Tuple[int, int]:
    """Return (n, d) from a PKCS#8 PEM RSA private key."""
    text = open(path, "r", encoding="ascii").read()
    b64 = "".join(
        line.strip()
        for line in text.splitlines()
        if line and not line.startswith("-----")
    )
    der = base64.b64decode(b64)
    top = _read_tlv_all(der)
    _, pk_info = top[0]
    pieces = _read_tlv_all(pk_info)
    # pieces: [INTEGER version, SEQUENCE algid, OCTET STRING pkcs1-key]
    pkcs1_der = pieces[2][1]
    rsa_seq = _read_tlv_all(pkcs1_der)[0][1]
    ints = [v for tag, v in _read_tlv_all(rsa_seq) if tag == 0x02]
    # version, n, e, d, p, q, dP, dQ, qInv
    n = int.from_bytes(ints[1], "big")
    d = int.from_bytes(ints[3], "big")
    return n, d


def rsa_sign_pkcs1_v15_sha256(
    n: int, d: int, message: bytes, fold: bool = True
) -> bytes:
    digest = hashlib.sha256(message).digest()
    t = _DIGEST_INFO_SHA256 + digest
    k = (n.bit_length() + 7) // 8
    if len(t) + 11 > k:
        raise ValueError("key too small")
    ps = b"\xff" * (k - len(t) - 3)
    em = b"\x00\x01" + ps + b"\x00" + t
    m = int.from_bytes(em, "big")
    s = pow(m, d, n)
    return s.to_bytes(k, "big")


# --------------------------------------------------------------------------
# Message signing
# --------------------------------------------------------------------------

def sign_message(
    headers: List[Tuple[str, str]],
    body: bytes,
    *,
    domain: str,
    selector: str,
    private_key_path: str,
    header_canon: str = "relaxed",
    body_canon: str = "relaxed",
    signed_headers: Optional[List[str]] = None,
    fold_b: bool = True,
    extra_tags: Optional[Dict[str, str]] = None,
    b_value: Optional[bytes] = None,
) -> bytes:
    """Build a signed RFC 822 message.

    ``headers`` are (name, value) pairs where value may already contain
    folding (CRLF + WSP).  ``body`` must be CRLF framed without trailing
    separator termination conventions mattering.
    """
    if signed_headers is None:
        signed_headers = [name.lower().split(":", 1)[0] for name, _ in headers]

    canon_body = (
        dkim_core.canonicalize_body_simple(body)
        if body_canon == "simple"
        else dkim_core.canonicalize_body_relaxed(body)
    )
    bh = hashlib.sha256(canon_body).digest()

    tags = {
        "v": "1",
        "a": "rsa-sha256",
        "c": f"{header_canon}/{body_canon}",
        "d": domain,
        "s": selector,
        "q": "dns/txt",
        "h": ":".join(signed_headers),
        "bh": base64.b64encode(bh).decode("ascii"),
        "b": "",
    }
    if extra_tags:
        tags.update(extra_tags)
    # b= must be the last tag so nothing else follows it.
    order = ["v", "a", "c", "d", "s", "q", "h", "bh"]
    order += [k for k in tags if k not in order + ["b"]]
    order += ["b"]
    tag_value = "; ".join(f"{k}={tags[k]}" for k in order)

    header_block = b"".join(
        _render_header(name, value) for name, value in headers
    )
    sig_raw = b"DKIM-Signature: " + tag_value.encode("ascii")
    sig_field = dkim_core.HeaderField(
        b"dkim-signature", sig_raw + b"\r\n"
    )
    fields = dkim_core.parse_header_fields(header_block)

    parsed = dkim_core.SignatureTags(
        raw=tags,
        domain=domain,
        selector=selector,
        algorithm="rsa-sha256",
        header_canon=header_canon,
        body_canon=body_canon,
        signed_headers=signed_headers,
        signature=b"",
        body_hash=bh,
    )
    chosen = dkim_core.select_header_indices(fields, signed_headers)
    canon = (
        dkim_core.canonicalize_header_simple
        if header_canon == "simple"
        else dkim_core.canonicalize_header_relaxed
    )
    signed_data = b"".join(canon(fields[i]) for i in chosen)
    signed_data += dkim_core.canonicalize_signature_header(
        sig_field, header_canon
    )

    if b_value is not None:
        signature = b_value
    else:
        n, d = load_rsa_private_key(private_key_path)
        signature = rsa_sign_pkcs1_v15_sha256(n, d, signed_data)
    b64sig = base64.b64encode(signature).decode("ascii")
    if fold_b:
        # RFC 6376 3.5: fold b= in 72-octor chunks.
        chunks = [b64sig[i:i + 72] for i in range(0, len(b64sig), 72)]
        rendered_b = ("\r\n\t".join(chunks)).encode("ascii")
        rendered_sig = sig_raw + rendered_b + b"\r\n"
    else:
        rendered_sig = sig_raw + b64sig.encode("ascii") + b"\r\n"

    return header_block + rendered_sig + b"\r\n" + body


def _render_header(name: str, value: str) -> bytes:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return name.encode("ascii") + b": " + raw + b"\r\n"
