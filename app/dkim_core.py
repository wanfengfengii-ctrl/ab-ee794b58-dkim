"""DKIM (RFC 6376) auditing core.

Pure standard-library implementation used by the forensic archive gateway to
re-verify externally submitted mail before archiving.  It performs:

* strict message framing checks (CRLF boundaries, single DKIM-Signature)
* simple / relaxed canonicalization for headers and body
* bottom-up selection of duplicate header fields per the h= tag
* independent body-hash and RSA-PKCS#1 v1.5 signature verdicts
* a strict tag policy (rsa-sha256 only, l= forbidden, From must be signed)

Every rejection carries a stable ``reason_code`` so downstream archiving can
distinguish digest failures from signature failures, unknown keys and policy
violations.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

MAX_MESSAGE_SIZE = 2 * 1024 * 1024  # 2 MiB

# Stable reason codes -------------------------------------------------------
OK = "OK"
NO_SIGNATURE = "NO_SIGNATURE"
MULTIPLE_SIGNATURES = "MULTIPLE_SIGNATURES"
MESSAGE_TOO_LARGE = "MESSAGE_TOO_LARGE"
MALFORMED_MESSAGE = "MALFORMED_MESSAGE"
MALFORMED_SIGNATURE = "MALFORMED_SIGNATURE"
NONCOMPLIANT_TAG = "NONCOMPLIANT_TAG"
L_TAG_FORBIDDEN = "L_TAG_FORBIDDEN"
FROM_NOT_SIGNED = "FROM_NOT_SIGNED"
UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"
UNSUPPORTED_CANONICALIZATION = "UNSUPPORTED_CANONICALIZATION"
UNKNOWN_KEY = "UNKNOWN_KEY"
KEY_UNAVAILABLE = "KEY_UNAVAILABLE"
BODY_HASH_MISMATCH = "BODY_HASH_MISMATCH"
SIGNATURE_MISMATCH = "SIGNATURE_MISMATCH"
INTERNAL_ERROR = "INTERNAL_ERROR"

ACCEPT = "accept"
REJECT = "reject"

_WSP = b" \t"
_CRLF = b"\r\n"
_FOLD_RE = re.compile(rb"\r\n[ \t]+")
_WSP_RUN_RE = re.compile(rb"[ \t]+")
_SP_RUN_RE = re.compile(rb" +")

# ASN.1 DigestInfo prefixes (RFC 8017 9.2, note 1)
_DIGEST_INFO_PREFIX = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
}


class DkimError(Exception):
    """Internal control-flow error carrying a stable reason code."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# --------------------------------------------------------------------------
# Message / header parsing
# --------------------------------------------------------------------------

@dataclass
class HeaderField:
    name: bytes            # lower-cased raw field name, e.g. b"from"
    raw: bytes             # full canonicalizable field incl. trailing CRLF


def _assert_crlf_framing(data: bytes) -> None:
    """The contract requires CRLF line boundaries with no bare CR/LF."""
    no_cr = data.replace(b"\r\n", b"")
    if b"\n" in no_cr or b"\r" in no_cr:
        raise DkimError(MALFORMED_MESSAGE)


def split_message(data: bytes) -> Tuple[bytes, bytes]:
    sep = data.find(b"\r\n\r\n")
    if sep < 0:
        raise DkimError(MALFORMED_MESSAGE)
    return data[:sep], data[sep + 4:]


def parse_header_fields(header_block: bytes) -> List[HeaderField]:
    """Split the header block into fields, honoring folded continuation lines."""
    groups: List[List[bytes]] = []
    current: Optional[List[bytes]] = None
    lines = header_block.split(b"\r\n")
    # A block ending in CRLF yields a trailing empty element; drop it.
    if lines and lines[-1] == b"":
        lines.pop()
    for line in lines:
        if line[:1] in (b" ", b"\t"):
            if current is None:
                raise DkimError(MALFORMED_MESSAGE)
            current.append(line)
        else:
            if current is not None:
                groups.append(current)
            current = [line]
    if current is not None:
        groups.append(current)

    fields: List[HeaderField] = []
    for group in groups:
        first = group[0]
        colon = first.find(b":")
        if colon <= 0:
            raise DkimError(MALFORMED_MESSAGE)
        name = first[:colon].lower()
        if not name or not _is_token_name(name):
            raise DkimError(MALFORMED_MESSAGE)
        raw = b"\r\n".join(group) + b"\r\n"
        fields.append(HeaderField(name=name, raw=raw))
    return fields


_TOKEN_RE = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_DOMAIN_RE = re.compile(
    r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_SELECTOR_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)


def _is_token_name(name: bytes) -> bool:
    return bool(_TOKEN_RE.match(name))


# --------------------------------------------------------------------------
# Canonicalization (RFC 6376 section 3.4)
# --------------------------------------------------------------------------

def canonicalize_body_simple(body: bytes) -> bytes:
    """Simple body: strip *all* trailing empty lines, then one CRLF.

    An empty body canonicalizes to a single CRLF.
    """
    stripped = body
    while stripped.endswith(b"\r\n"):
        stripped = stripped[:-2]
    if not stripped:
        return b"\r\n"
    return stripped + b"\r\n"


def canonicalize_body_relaxed(body: bytes) -> bytes:
    """Relaxed body: tabs->spaces, collapse WSP runs, trim line ends, drop
    trailing empty lines, terminate with one CRLF."""
    lines = body.split(b"\r\n")
    while lines and lines[-1] == b"":
        lines.pop()
    canon_lines: List[bytes] = []
    for line in lines:
        line = line.replace(b"\t", b" ")
        line = _SP_RUN_RE.sub(b" ", line)
        line = line.rstrip(b" ")
        canon_lines.append(line)
    if not canon_lines:
        return b"\r\n"
    return b"\r\n".join(canon_lines) + b"\r\n"


def canonicalize_header_simple(field: HeaderField) -> bytes:
    """Simple header canonicalization leaves the field untouched."""
    return field.raw


def canonicalize_header_relaxed(field: HeaderField) -> bytes:
    """Relaxed header: unfold, lowercase name, trim around colon/ends,
    collapse WSP runs."""
    unfolded = _FOLD_RE.sub(b" ", field.raw)
    if unfolded.endswith(b"\r\n"):
        unfolded = unfolded[:-2]
    name, _, value = unfolded.partition(b":")
    value = value.strip(_WSP)
    value = _WSP_RUN_RE.sub(b" ", value)
    return name.lower() + b":" + value + b"\r\n"


def _erase_b_value(data: bytes) -> bytes:
    """Replace the b= tag payload with the empty string.

    Operates on data that either keeps folding (simple) or has already been
    unfolded (relaxed); a following ``;``-delimited tag is preserved.  The
    ``b=`` occurrence must start an actual tag (preceded only by the colon, a
    semicolon and/or folding whitespace) so a ``b=`` substring inside another
    tag value cannot fool the erasure.
    """
    match = None
    for cand in re.finditer(rb"b=", data):
        before = _FOLD_RE.sub(b" ", data[: cand.start()]).rstrip(b" \t")
        if before.endswith(b":") or before.endswith(b";"):
            match = cand
            break
    if match is None:
        raise DkimError(MALFORMED_SIGNATURE)
    start = match.end()
    semi = data.find(b";", start)
    if semi < 0:
        return data[:start]
    return data[:start] + data[semi:]


def canonicalize_signature_header(field: HeaderField, header_alg: str) -> bytes:
    """Canonicalize the DKIM-Signature field itself for the signed data.

    The b= tag value is emptied per RFC 6376 3.7 (folding inside it counts as
    part of the value and is removed together with the base64 data).
    """
    if header_alg == "simple":
        raw = field.raw
        terminator = b""
        if raw.endswith(b"\r\n"):
            raw, terminator = raw[:-2], b"\r\n"
        return _erase_b_value(raw) + terminator

    unfolded = _FOLD_RE.sub(b" ", field.raw)
    if unfolded.endswith(b"\r\n"):
        unfolded = unfolded[:-2]
    name, _, value = unfolded.partition(b":")
    value = value.strip(_WSP)
    value = _WSP_RUN_RE.sub(b" ", value)
    value = _erase_b_value(value)
    return name.lower() + b":" + value + b"\r\n"


# --------------------------------------------------------------------------
# DKIM tag parsing / policy
# --------------------------------------------------------------------------

@dataclass
class SignatureTags:
    raw: Dict[str, str]
    domain: str
    selector: str
    algorithm: str
    header_canon: str
    body_canon: str
    signed_headers: List[str]
    signature: bytes       # decoded b=
    body_hash: bytes       # decoded bh=


def _unfold_field(field: HeaderField) -> bytes:
    unfolded = _FOLD_RE.sub(b" ", field.raw)
    if unfolded.endswith(b"\r\n"):
        unfolded = unfolded[:-2]
    return unfolded


def _b64_decode_tag(value: str) -> bytes:
    compact = "".join(value.split())
    if compact == "":
        return b""
    try:
        return base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DkimError(MALFORMED_SIGNATURE) from exc


def parse_signature_tags(field: HeaderField) -> SignatureTags:
    unfolded = _unfold_field(field)
    try:
        text = unfolded.decode("ascii")
    except UnicodeDecodeError as exc:
        raise DkimError(MALFORMED_SIGNATURE) from exc

    _, _, tag_section = text.partition(":")
    tags: Dict[str, str] = {}
    for spec in tag_section.split(";"):
        spec = spec.strip()
        if spec == "":
            continue  # trailing semicolon / empty spec is harmless
        if "=" not in spec:
            raise DkimError(NONCOMPLIANT_TAG)
        key, _, val = spec.partition("=")
        key = key.strip().lower()
        val = val.strip()
        if key == "" or key in tags:
            # empty tag name or a tag appearing more than once is non-compliant
            raise DkimError(NONCOMPLIANT_TAG)
        tags[key] = val

    required = ("v", "a", "b", "bh", "d", "h", "s")
    if any(t not in tags for t in required):
        raise DkimError(MALFORMED_SIGNATURE)

    if tags["v"] != "1":
        raise DkimError(NONCOMPLIANT_TAG)
    if tags.get("q", "dns/txt") != "dns/txt":
        raise DkimError(NONCOMPLIANT_TAG)

    if "l" in tags:
        raise DkimError(L_TAG_FORBIDDEN)

    algorithm = tags["a"].lower()
    if algorithm != "rsa-sha256":
        raise DkimError(UNSUPPORTED_ALGORITHM)

    canon = tags.get("c", "simple/simple").lower()
    if "/" in canon:
        header_canon, body_canon = (x.strip() for x in canon.split("/", 1))
    else:
        header_canon, body_canon = canon.strip(), "simple"
    if header_canon not in ("simple", "relaxed") or body_canon not in (
        "simple",
        "relaxed",
    ):
        raise DkimError(UNSUPPORTED_CANONICALIZATION)

    signed_headers = [h.strip().lower() for h in tags["h"].split(":")]
    signed_headers = [h for h in signed_headers if h != ""]
    if "from" not in signed_headers:
        raise DkimError(FROM_NOT_SIGNED)
    # RFC 6376 5.4.2: the DKIM-Signature field itself is never signed.
    if "dkim-signature" in signed_headers:
        raise DkimError(NONCOMPLIANT_TAG)

    domain = tags["d"]
    selector = tags["s"]
    if len(domain) > 255 or not _DOMAIN_RE.match(domain):
        raise DkimError(NONCOMPLIANT_TAG)
    if len(selector) > 255 or not _SELECTOR_RE.match(selector):
        raise DkimError(NONCOMPLIANT_TAG)

    signature = _b64_decode_tag(tags["b"])
    if not signature:
        raise DkimError(MALFORMED_SIGNATURE)
    body_hash = _b64_decode_tag(tags["bh"])

    return SignatureTags(
        raw=tags,
        domain=domain,
        selector=selector,
        algorithm=algorithm,
        header_canon=header_canon,
        body_canon=body_canon,
        signed_headers=signed_headers,
        signature=signature,
        body_hash=body_hash,
    )


# --------------------------------------------------------------------------
# Signed-data assembly (bottom-up duplicate header selection)
# --------------------------------------------------------------------------

def select_header_indices(
    fields: List[HeaderField], signed_headers: List[str]
) -> List[int]:
    """Resolve h= names to field indices using bottom-up selection.

    Each occurrence of a name in h= consumes the lowest-not-yet-consumed
    occurrence counting from the bottom; i.e. the first reference selects the
    last field of that name, the second the second-last, and so on.
    """
    buckets: Dict[bytes, List[int]] = {}
    for idx, fld in enumerate(fields):
        buckets.setdefault(fld.name, []).append(idx)

    chosen: List[int] = []
    for name in signed_headers:
        lst = buckets.get(name.encode("ascii"))
        if lst:
            chosen.append(lst.pop())
        # A missing header contributes nothing to the signed data (RFC 3.7).
    return chosen


def build_signing_data(
    fields: List[HeaderField],
    sig_field: HeaderField,
    parsed: SignatureTags,
) -> bytes:
    if parsed.header_canon == "simple":
        header_canon = canonicalize_header_simple
    else:
        header_canon = canonicalize_header_relaxed

    parts = [
        header_canon(fields[i])
        for i in select_header_indices(fields, parsed.signed_headers)
    ]
    parts.append(
        canonicalize_signature_header(sig_field, parsed.header_canon)
    )
    return b"".join(parts)


# --------------------------------------------------------------------------
# RSA public-key handling and verification
# --------------------------------------------------------------------------

def _read_tlv(data: bytes, offset: int) -> Tuple[int, bytes, int]:
    if offset >= len(data):
        raise ValueError("truncated DER")
    tag = data[offset]
    length = data[offset + 1]
    pos = offset + 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or pos + n > len(data):
            raise ValueError("bad DER length")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    if pos + length > len(data):
        raise ValueError("truncated DER value")
    return tag, data[pos:pos + length], pos + length


def parse_rsa_public_key(spki_der: bytes) -> Tuple[int, int]:
    """Parse a SubjectPublicKeyInfo DER blob and return (modulus, exponent)."""
    tag, spki, _ = _read_tlv(spki_der, 0)
    if tag != 0x30:
        raise ValueError("expected SEQUENCE")
    tag, _algid, pos = _read_tlv(spki, 0)
    if tag != 0x30:
        raise ValueError("expected AlgorithmIdentifier")
    tag, bitstr, _ = _read_tlv(spki, pos)
    if tag != 0x03 or not bitstr or bitstr[0] != 0x00:
        raise ValueError("expected unused-bits 0 BIT STRING")
    rsa_der = bitstr[1:]
    tag, rsa_seq, _ = _read_tlv(rsa_der, 0)
    if tag != 0x30:
        raise ValueError("expected RSAPublicKey")
    tag, mod_bytes, pos = _read_tlv(rsa_seq, 0)
    if tag != 0x02:
        raise ValueError("expected modulus INTEGER")
    tag, exp_bytes, _ = _read_tlv(rsa_seq, pos)
    if tag != 0x02:
        raise ValueError("expected exponent INTEGER")
    modulus = int.from_bytes(mod_bytes, "big")
    exponent = int.from_bytes(exp_bytes, "big")
    if modulus <= 0 or exponent <= 0:
        raise ValueError("non-positive RSA parameter")
    return modulus, exponent


def _rsa_pkcs1_verify(
    modulus: int, exponent: int, signature: bytes, encoded_message: bytes
) -> bool:
    """Check EMSA-PKCS1-v1_5 (RFC 8017 8.2.2): EM = 0x00 0x01 PS 0x00 T."""
    key_bytes = (modulus.bit_length() + 7) // 8
    if len(signature) != key_bytes:
        return False
    if key_bytes < len(encoded_message) + 11:
        return False
    expected = (
        b"\x00\x01"
        + b"\xff" * (key_bytes - len(encoded_message) - 3)
        + b"\x00"
        + encoded_message
    )
    s_int = int.from_bytes(signature, "big")
    if s_int >= modulus:
        return False
    recovered = pow(s_int, exponent, modulus).to_bytes(key_bytes, "big")
    return hmac.compare_digest(recovered, expected)


def load_keyring(path: str) -> Dict[str, Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("keyring must be an object keyed by domain")
    return data


def lookup_public_key(
    keyring: Dict[str, Dict[str, Any]], domain: str, selector: str
) -> Tuple[int, int]:
    # DNS labels are case-insensitive; keyring keys are registered lowercase.
    domain = domain.lower()
    selector = selector.lower()
    selectors = keyring.get(domain)
    if not isinstance(selectors, dict):
        raise DkimError(UNKNOWN_KEY)
    entry = selectors.get(selector)
    if not isinstance(entry, dict) or "p" not in entry:
        raise DkimError(UNKNOWN_KEY)
    p_value = entry["p"]
    if not isinstance(p_value, str):
        raise DkimError(KEY_UNAVAILABLE)
    # Accept both the RFC 3110 bare RSAPublicKey SEQUENCE (the shape DNS TXT
    # p= tags actually carry) and a full SubjectPublicKeyInfo.
    try:
        der = base64.b64decode("".join(p_value.split()), validate=True)
        tag, outer, _ = _read_tlv(der, 0)
        if tag != 0x30:
            raise ValueError
        first_tag, _, _ = _read_tlv(outer, 0)
        if first_tag == 0x02:
            # Bare RSAPublicKey: SEQUENCE { n INTEGER, e INTEGER }
            der = _wrap_bare_rsa_key(der)
        elif first_tag != 0x30:
            raise ValueError
        return parse_rsa_public_key(der)
    except (ValueError, binascii.Error) as exc:
        raise DkimError(KEY_UNAVAILABLE) from exc


def _der_tlv(tag: int, value: bytes) -> bytes:
    n = len(value)
    if n < 0x80:
        length = bytes([n])
    else:
        octets = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(octets)]) + octets
    return bytes([tag]) + length + value


def _wrap_bare_rsa_key(rsa_der: bytes) -> bytes:
    """Wrap a bare RFC 3110 RSAPublicKey into SubjectPublicKeyInfo."""
    algid = bytes.fromhex("300d06092a864886f70d0101010500")  # rsaEncryption
    bit_string = _der_tlv(0x03, b"\x00" + rsa_der)
    return _der_tlv(0x30, algid + bit_string)


# --------------------------------------------------------------------------
# Top-level audit
# --------------------------------------------------------------------------

@dataclass
class AuditResult:
    decision: str = REJECT
    reason_code: str = MALFORMED_MESSAGE
    domain: Optional[str] = None
    selector: Optional[str] = None
    algorithm: Optional[str] = None
    canonicalization: Optional[Dict[str, str]] = None
    signed_headers: List[str] = field(default_factory=list)
    body: Optional[Dict[str, Any]] = None
    signature_verdict: Optional[str] = None
    signature_detail: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "decision": self.decision,
            "reason_code": self.reason_code,
            "domain": self.domain,
            "selector": self.selector,
            "algorithm": self.algorithm,
            "canonicalization": self.canonicalization,
            "signed_headers": self.signed_headers,
            "body_verdict": self.body,
            "signature_verdict": self.signature_verdict,
            "signature_detail": self.signature_detail,
        }
        return out


def audit(data: bytes, keyring: Dict[str, Dict[str, Any]]) -> Audit:
    """Audit one raw RFC 822 message and return independent verdicts."""
    result = AuditResult()
    try:
        if len(data) > MAX_MESSAGE_SIZE:
            result.reason_code = MESSAGE_TOO_LARGE
            return result
        _assert_crlf_framing(data)
        header_block, body = split_message(data)
        fields = parse_header_fields(header_block)

        sig_indices = [i for i, f in enumerate(fields) if f.name == b"dkim-signature"]
        if len(sig_indices) == 0:
            result.reason_code = NO_SIGNATURE
            return result
        if len(sig_indices) > 1:
            result.reason_code = MULTIPLE_SIGNATURES
            return result
        sig_field = fields[sig_indices[0]]
        parsed = parse_signature_tags(sig_field)
        result.domain = parsed.domain
        result.selector = parsed.selector
        result.algorithm = parsed.algorithm
        result.canonicalization = {
            "headers": parsed.header_canon,
            "body": parsed.body_canon,
        }
        result.signed_headers = parsed.signed_headers

        # --- independent verdict 1: body digest --------------------------
        if parsed.body_canon == "simple":
            canon_body = canonicalize_body_simple(body)
        else:
            canon_body = canonicalize_body_relaxed(body)
        computed = hashlib.sha256(canon_body).digest()
        body_match = hmac.compare_digest(computed, parsed.body_hash)
        result.body = {
            "verdict": "pass" if body_match else "fail",
            "algorithm": "sha256",
            "declared_bh": base64.b64encode(parsed.body_hash).decode("ascii"),
            "computed": base64.b64encode(computed).decode("ascii"),
            "canonicalization": parsed.body_canon,
        }

        # --- independent verdict 2: cryptographic signature --------------
        # verdict is "pass" / "fail" only when a key was available; with no
        # registered/usable key the cryptographic question is "indeterminate"
        # and the stable reason code carries UNKNOWN_KEY / KEY_UNAVAILABLE.
        sig_verdict = "indeterminate"
        sig_detail = "key_unavailable"
        key_error: Optional[str] = None
        try:
            modulus, exponent = lookup_public_key(
                keyring, parsed.domain, parsed.selector
            )
            signing_data = build_signing_data(fields, sig_field, parsed)
            digest = hashlib.sha256(signing_data).digest()
            encoded = _DIGEST_INFO_PREFIX["sha256"] + digest
            if _rsa_pkcs1_verify(modulus, exponent, parsed.signature, encoded):
                sig_verdict, sig_detail = "pass", "verified"
            else:
                sig_verdict, sig_detail = "fail", "rsa_pkcs1_verify_failed"
        except DkimError as exc:
            key_error = exc.reason
            sig_detail = exc.reason
        result.signature_verdict = sig_verdict
        result.signature_detail = sig_detail

        # --- aggregate ----------------------------------------------------
        if key_error is not None:
            result.reason_code = key_error
        elif not body_match:
            result.reason_code = BODY_HASH_MISMATCH
        elif sig_verdict != "pass":
            result.reason_code = SIGNATURE_MISMATCH
        else:
            result.reason_code = OK
            result.decision = ACCEPT
        return result

    except DkimError as exc:
        result.reason_code = exc.reason
        return result
    except Exception:  # never leak a stack trace to the archiver
        result.reason_code = INTERNAL_ERROR
        return result


# Re-exported type alias kept after AuditResult for readability
Audit = AuditResult
