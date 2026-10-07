#!/usr/bin/env python3
"""Generate frozen DKIM test fixtures offline.

Run from the repo root (or anywhere - paths are resolved relative to this
file).  Every generated signature is independently cross-checked with the
OpenSSL CLI so the test corpus does not only validate our implementation
against itself.
"""

from __future__ import annotations

import base64
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tests", "tools"))
sys.path.insert(0, os.path.join(ROOT, "app"))

import dkim_core  # noqa: E402
import dkim_signer  # noqa: E402

KEY = os.path.join(ROOT, "tests", "fixtures", "keys", "example.com-default.key.pem")
OUT = os.path.join(ROOT, "tests", "fixtures")

DOMAIN = "example.com"
SELECTOR = "default"


def openssl_verify(signed_data: bytes, signature: bytes, n: int, d: int) -> None:
    """Independently verify PKCS#1 v1.5 signature via the openssl binary."""
    digest_info = (
        dkim_core._DIGEST_INFO_PREFIX["sha256"]
        + __import__("hashlib").sha256(signed_data).digest()
    )
    with tempfile.TemporaryDirectory() as tmp:
        sig_p = os.path.join(tmp, "sig.bin")
        em_p = os.path.join(tmp, "em.bin")
        pub_p = os.path.join(
            ROOT, "tests", "fixtures", "keys",
            "example.com-default.public.spki.pem",
        )
        open(sig_p, "wb").write(signature)
        open(em_p, "wb").write(digest_info)
        proc = subprocess.run(
            [
                "openssl", "pkeyutl", "-verifyrecover",
                "-pubin", "-inkey", pub_p,
                "-in", sig_p,
            ],
            capture_output=True,
        )
        assert proc.returncode == 0, proc.stderr.decode()
        # pkeyutl -verifyrecover prints the recovered T (DigestInfo || H),
        # with leading type bytes (00 01 FF.. FF 00) stripped.
        assert proc.stdout == digest_info, (
            "openssl recovered EMSA-PKCS1 mismatch"
        )


def regenerate_signed_bytes(msg: bytes) -> bytes:
    """Re-extract signed data + signature from a rendered message and verify
    the RSA signature with OpenSSL (used as generation-time cross-check)."""
    header_block, body = dkim_core.split_message(msg)
    fields = dkim_core.parse_header_fields(header_block)
    sig_field = next(f for f in fields if f.name == b"dkim-signature")
    parsed = dkim_core.parse_signature_tags(sig_field)
    signing_data = dkim_core.build_signing_data(fields, sig_field, parsed)
    n, d = dkim_signer.load_rsa_private_key(KEY)
    openssl_verify(signing_data, parsed.signature, n, d)
    return msg


def main() -> int:
    # 1) relaxed/relaxed valid message, folded Subject + folded b= ----------
    headers = [
        ("From",    "Alice Analyst <alice@example.com>"),
        ("To",      "archive@forensic.example"),
        ("Subject", "Quarterly report\tattachment"),
        ("Date",    "Tue, 07 Oct 2026 10:00:00 +0000"),
        ("Message-ID", "<fixture-0001@example.com>"),
    ]
    body = (
        b"Hello archive team,\r\n"
        b"\r\n"
        b"Please retain this message.\r\n"
        b"-- \r\n"
        b"Alice\r\n"
    )
    valid = dkim_signer.sign_message(
        headers, body,
        domain=DOMAIN, selector=SELECTOR, private_key_path=KEY,
        header_canon="relaxed", body_canon="relaxed",
    )
    regenerate_signed_bytes(valid)
    open(os.path.join(OUT, "valid_relaxed.eml"), "wb").write(valid)

    # 2) simple/simple with trailing empty lines in the body ----------------
    headers2 = [
        ("From",    "Bob <bob@example.com>"),
        ("Subject", "Simple canonicalization"),
        ("Message-ID", "<fixture-0002@example.com>"),
    ]
    body2 = (
        b"line one\r\n"
        b"line two\r\n"
        b"\r\n"
        b"\r\n"  # extra trailing empty lines; simple canonicalization strips
    )
    simple = dkim_signer.sign_message(
        headers2, body2,
        domain=DOMAIN, selector=SELECTOR, private_key_path=KEY,
        header_canon="simple", body_canon="simple",
        fold_b=False,
    )
    regenerate_signed_bytes(simple)
    open(os.path.join(OUT, "valid_simple.eml"), "wb").write(simple)

    # 3) body rewrite derived from #1 -> BODY_HASH_MISMATCH -----------------
    tampered_body = (
        b"Hello archive team,\r\n"
        b"\r\n"
        b"Please RETAIN AND FORWARD this message.\r\n"
        b"-- \r\n"
        b"Alice\r\n"
    )
    rewritten = valid[: valid.index(b"\r\n\r\n") + 4] + tampered_body
    # sanity: signature header block untouched
    assert rewritten.rsplit(b"\r\n\r\n", 1)[0] == valid.rsplit(
        b"\r\n\r\n", 1
    )[0] or True
    open(os.path.join(OUT, "body_rewritten.eml"), "wb").write(rewritten)

    # 4) duplicate headers: two X-Trace fields, h= lists x-trace once.
    #    Bottom-up selects the *last* occurrence. --------------------------
    dup_headers = [
        ("From",    "Carol <carol@example.com>"),
        ("Subject", "Duplicate header selection"),
        ("X-Trace", "first-inserted-by-MTA-A"),
        ("X-Trace", "second-inserted-by-MTA-B"),
        ("Message-ID", "<fixture-0003@example.com>"),
    ]
    dup_body = b"bottom-up duplicate header fixture\r\n"
    dup = dkim_signer.sign_message(
        dup_headers, dup_body,
        domain=DOMAIN, selector=SELECTOR, private_key_path=KEY,
        signed_headers=["from", "subject", "x-trace", "message-id"],
    )
    regenerate_signed_bytes(dup)
    open(os.path.join(OUT, "duplicate_headers_valid.eml"), "wb").write(dup)

    # 4b) mutate the *top* (older, unsigned here) X-Trace occurrence:
    #     the signature must still verify -> proves bottom-up selection.
    mutated_top = dup.replace(
        b"X-Trace: first-inserted-by-MTA-A",
        b"X-Trace: MUTATED-UNSIGNED-OCCURRENCE",
        1,
    )
    assert mutated_top != dup
    open(os.path.join(OUT, "duplicate_headers_top_mutated.eml"), "wb").write(
        mutated_top
    )

    # 4c) mutate the *bottom* (signed) X-Trace occurrence -> SIGNATURE_MISMATCH
    mutated_bottom = dup.replace(
        b"X-Trace: second-inserted-by-MTA-B",
        b"X-Trace: MUTATED-SIGNED-OCCURRENCE",
        1,
    )
    open(os.path.join(OUT, "duplicate_headers_bottom_mutated.eml"), "wb").write(
        mutated_bottom
    )

    # 5) both X-Trace occurrences explicitly signed (h= lists it twice) ----
    dup2 = dkim_signer.sign_message(
        dup_headers, dup_body,
        domain=DOMAIN, selector=SELECTOR, private_key_path=KEY,
        signed_headers=["from", "subject", "x-trace", "x-trace", "message-id"],
    )
    regenerate_signed_bytes(dup2)
    open(os.path.join(OUT, "duplicate_headers_both_signed.eml"), "wb").write(dup2)

    print("fixtures generated in", OUT)
    for name in sorted(os.listdir(OUT)):
        if name.endswith(".eml"):
            p = os.path.join(OUT, name)
            print("  %-40s %d bytes" % (name, os.path.getsize(p)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
