"""Unit tests for DKIM canonicalization, framing, tag policy and selection."""

from __future__ import annotations

import base64
import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "app"))

import dkim_core as dc  # noqa: E402

KEYRING = dc.load_keyring(
    os.environ.get("DKIM_KEYRING", os.path.join(ROOT, "config", "keyring.json"))
)
FIX = os.path.join(ROOT, "tests", "fixtures")


def fixture(name: str) -> bytes:
    with open(os.path.join(FIX, name), "rb") as handle:
        return handle.read()


class CanonicalizationTests(unittest.TestCase):
    def test_simple_body_strips_trailing_empty_lines(self):
        self.assertEqual(
            dc.canonicalize_body_simple(b"a\r\nb\r\n\r\n\r\n"),
            b"a\r\nb\r\n",
        )
        self.assertEqual(dc.canonicalize_body_simple(b""), b"\r\n")
        self.assertEqual(dc.canonicalize_body_simple(b"\r\n\r\n"), b"\r\n")

    def test_relaxed_body_rules(self):
        # tab -> space, WSP collapse, trim trailing WSP; trailing empty lines
        # are removed but interior empty lines are preserved
        body = b"x\t y \r\n\r\nz   \r\n\r\n"
        self.assertEqual(
            dc.canonicalize_body_relaxed(body),
            b"x y\r\n\r\nz\r\n",
        )
        self.assertEqual(dc.canonicalize_body_relaxed(b""), b"\r\n")

    def test_relaxed_header_unfolding(self):
        fld = dc.HeaderField(
            b"subject", b"Subject: hello\r\n\tworld  \r\n"
        )
        self.assertEqual(
            dc.canonicalize_header_relaxed(fld),
            b"subject:hello world\r\n",
        )

    def test_simple_header_untouched(self):
        fld = dc.HeaderField(b"x", b"X:  a \r\n\tb \r\n")
        self.assertEqual(
            dc.canonicalize_header_simple(fld), b"X:  a \r\n\tb \r\n"
        )

    def test_signature_header_b_erasure_simple(self):
        fld = dc.HeaderField(
            b"dkim-signature",
            b"DKIM-Signature: v=1; b=abc\r\n\tdef; bh=zzz\r\n",
        )
        self.assertEqual(
            dc.canonicalize_signature_header(fld, "simple"),
            b"DKIM-Signature: v=1; b=; bh=zzz\r\n",
        )

    def test_signature_header_b_erasure_relaxed(self):
        fld = dc.HeaderField(
            b"dkim-signature",
            b"DKIM-Signature: v=1;  b=abc\r\n\t def; bh=zzz  \r\n",
        )
        self.assertEqual(
            dc.canonicalize_signature_header(fld, "relaxed"),
            b"dkim-signature:v=1; b=; bh=zzz\r\n",
        )

    def test_b_erasure_ignores_b_substring_in_bh(self):
        # bh= base64 payload happens to contain "b="; only the real b= tag
        # (anchored after ';' or ':') may be erased.
        fld = dc.HeaderField(
            b"dkim-signature",
            b"DKIM-Signature: v=1; bh=Aabb=zz; b=SIGDATA\r\n",
        )
        out = dc.canonicalize_signature_header(fld, "simple")
        self.assertIn(b"bh=Aabb=zz", out)
        self.assertTrue(out.rstrip(b"\r\n").endswith(b"b="), out)
        self.assertNotIn(b"SIGDATA", out)


class FramingTests(unittest.TestCase):
    def test_bare_lf_rejected(self):
        with self.assertRaises(dc.DkimError) as ctx:
            dc._assert_crlf_framing(b"From: a\r\nX: y\n\r\nbody\r\n")
        self.assertEqual(ctx.exception.reason, dc.MALFORMED_MESSAGE)

    def test_header_block_required(self):
        with self.assertRaises(dc.DkimError):
            dc.split_message(b"no header separator at all")

    def test_folded_header_parsed(self):
        block = b"Subject: one\r\n\ttwo\r\nX: y\r\n"
        fields = dc.parse_header_fields(block)
        self.assertEqual([f.name for f in fields], [b"subject", b"x"])
        self.assertEqual(fields[0].raw, b"Subject: one\r\n\ttwo\r\n")

    def test_bad_field_name(self):
        with self.assertRaises(dc.DkimError):
            dc.parse_header_fields(b"nocolon\r\n")


class BottomUpSelectionTests(unittest.TestCase):
    def _fields(self, names):
        return [dc.HeaderField(n.encode(), n.encode() + b": v\r\n") for n in names]

    def test_duplicate_selects_last_then_second_last(self):
        fields = self._fields(["from", "x", "x", "to"])
        idx = dc.select_header_indices(fields, ["from", "x", "to", "x"])
        self.assertEqual(idx, [0, 2, 3, 1])

    def test_missing_header_consumes_nothing(self):
        fields = self._fields(["from"])
        self.assertEqual(dc.select_header_indices(fields, ["from", "resent-from"]), [0])


class FixtureVerdictTests(unittest.TestCase):
    def test_valid_relaxed_accepted(self):
        r = dc.audit(fixture("valid_relaxed.eml"), KEYRING)
        self.assertEqual(r.decision, dc.ACCEPT)
        self.assertEqual(r.reason_code, dc.OK)
        self.assertEqual(r.canonicalization, {"headers": "relaxed", "body": "relaxed"})
        self.assertEqual(r.domain, "example.com")
        self.assertEqual(r.selector, "default")
        self.assertEqual(r.body["verdict"], "pass")
        self.assertEqual(r.signature_verdict, "pass")
        self.assertIn("from", r.signed_headers)

    def test_valid_simple_accepted(self):
        r = dc.audit(fixture("valid_simple.eml"), KEYRING)
        self.assertEqual((r.decision, r.reason_code), (dc.ACCEPT, dc.OK))

    def test_body_rewrite_distinct_body_failure_signature_still_pass(self):
        r = dc.audit(fixture("body_rewritten.eml"), KEYRING)
        self.assertEqual(r.decision, dc.REJECT)
        self.assertEqual(r.reason_code, dc.BODY_HASH_MISMATCH)
        self.assertEqual(r.body["verdict"], "fail")
        self.assertNotEqual(r.body["declared_bh"], r.body["computed"])
        # The signature covers headers only; an untouched header block means
        # the cryptographic signature independently still verifies.
        self.assertEqual(r.signature_verdict, "pass")

    def test_duplicate_headers_valid_uses_bottom_occurrence(self):
        r = dc.audit(fixture("duplicate_headers_valid.eml"), KEYRING)
        self.assertEqual((r.decision, r.reason_code), (dc.ACCEPT, dc.OK))

    def test_mutating_unsigned_top_duplicate_still_verifies(self):
        r = dc.audit(fixture("duplicate_headers_top_mutated.eml"), KEYRING)
        self.assertEqual((r.decision, r.reason_code), (dc.ACCEPT, dc.OK))

    def test_mutating_signed_bottom_duplicate_fails_signature(self):
        r = dc.audit(fixture("duplicate_headers_bottom_mutated.eml"), KEYRING)
        self.assertEqual(r.reason_code, dc.SIGNATURE_MISMATCH)
        self.assertEqual(r.body["verdict"], "pass")
        self.assertEqual(r.signature_verdict, "fail")

    def test_both_duplicate_occurrences_signed(self):
        r = dc.audit(fixture("duplicate_headers_both_signed.eml"), KEYRING)
        self.assertEqual((r.decision, r.reason_code), (dc.ACCEPT, dc.OK))


class NegativePolicyTests(unittest.TestCase):
    BASE_HEADERS = (
        b"From: a@example.com\r\n"
        b"Subject: s\r\n"
    )

    def _audit_signature(self, sig_header: bytes, body: bytes = b"hi\r\n"):
        msg = self.BASE_HEADERS + sig_header + b"\r\n" + body
        return dc.audit(msg, KEYRING)

    def test_no_signature(self):
        r = dc.audit(b"From: a@example.com\r\n\r\nbody\r\n", KEYRING)
        self.assertEqual(r.reason_code, dc.NO_SIGNATURE)

    def test_multiple_signatures(self):
        sig = (
            b"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=default;\r\n"
            b" h=from; bh=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=; b=AAAA\r\n"
        )
        msg = self.BASE_HEADERS + sig + sig + b"\r\nx\r\n"
        r = dc.audit(msg, KEYRING)
        self.assertEqual(r.reason_code, dc.MULTIPLE_SIGNATURES)

    def test_l_tag_forbidden(self):
        r = self._audit_signature(
            b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n"
            b" d=example.com; s=default; h=from; l=12;\r\n"
            b" bh=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=; b=AAAA\r\n"
        )
        self.assertEqual(r.reason_code, dc.L_TAG_FORBIDDEN)

    def test_unsupported_algorithm(self):
        r = self._audit_signature(
            b"DKIM-Signature: v=1; a=rsa-sha1; d=example.com; s=default;\r\n"
            b" h=from; bh=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=; b=AAAA\r\n"
        )
        self.assertEqual(r.reason_code, dc.UNSUPPORTED_ALGORITHM)

    def test_unsupported_canonicalization(self):
        r = self._audit_signature(
            b"DKIM-Signature: v=1; a=rsa-sha256; c=norelax/simple;\r\n"
            b" d=example.com; s=default; h=from;\r\n"
            b" bh=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=; b=AAAA\r\n"
        )
        self.assertEqual(r.reason_code, dc.UNSUPPORTED_CANONICALIZATION)

    def test_from_not_signed(self):
        r = self._audit_signature(
            b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n"
            b" d=example.com; s=default; h=subject;\r\n"
            b" bh=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=; b=AAAA\r\n"
        )
        self.assertEqual(r.reason_code, dc.FROM_NOT_SIGNED)

    def test_unknown_key(self):
        r = self._audit_signature(
            b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n"
            b" d=unknown.example; s=default; h=from;\r\n"
            b" bh=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=; b=AAAA\r\n"
        )
        self.assertEqual(r.reason_code, dc.UNKNOWN_KEY)
        self.assertEqual(r.signature_verdict, "indeterminate")

    def test_unknown_selector(self):
        r = self._audit_signature(
            b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n"
            b" d=example.com; s=nosuchselector; h=from;\r\n"
            b" bh=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=; b=AAAA\r\n"
        )
        self.assertEqual(r.reason_code, dc.UNKNOWN_KEY)
        self.assertEqual(r.signature_verdict, "indeterminate")

    def test_corrupt_key_data(self):
        ring = {"example.com": {"default": {"p": "@@@@not-base64@@@@"}}}
        msg = (
            b"From: a@example.com\r\n"
            b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n"
            b" d=example.com; s=default; h=from;\r\n"
            b" bh=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=; b=AAAA\r\n"
            b"\r\nbody\r\n"
        )
        r = dc.audit(msg, ring)
        self.assertEqual(r.reason_code, dc.KEY_UNAVAILABLE)
        self.assertEqual(r.signature_verdict, "indeterminate")

    def test_duplicate_tag_rejected(self):
        r = self._audit_signature(
            b"DKIM-Signature: v=1; v=1; a=rsa-sha256; d=example.com;\r\n"
            b" s=default; h=from; bh=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=;\r\n"
            b" b=AAAA\r\n"
        )
        self.assertEqual(r.reason_code, dc.NONCOMPLIANT_TAG)

    def test_bad_version(self):
        r = self._audit_signature(
            b"DKIM-Signature: v=2; a=rsa-sha256; d=example.com; s=default;\r\n"
            b" h=from; bh=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=; b=AAAA\r\n"
        )
        self.assertEqual(r.reason_code, dc.NONCOMPLIANT_TAG)

    def test_bad_domain(self):
        r = self._audit_signature(
            b"DKIM-Signature: v=1; a=rsa-sha256; d=bad domain; s=default;\r\n"
            b" h=from; bh=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=; b=AAAA\r\n"
        )
        self.assertEqual(r.reason_code, dc.NONCOMPLIANT_TAG)

    def test_dkim_signature_in_h_rejected(self):
        r = self._audit_signature(
            b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n"
            b" d=example.com; s=default; h=from:dkim-signature;\r\n"
            b" bh=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=; b=AAAA\r\n"
        )
        self.assertEqual(r.reason_code, dc.NONCOMPLIANT_TAG)

    def test_malformed_base64_b(self):
        r = self._audit_signature(
            b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n"
            b" d=example.com; s=default; h=from;\r\n"
            b" bh=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=; b=@@notb64@@\r\n"
        )
        self.assertEqual(r.reason_code, dc.MALFORMED_SIGNATURE)

    def test_tampered_signature_value(self):
        msg = bytearray(fixture("valid_relaxed.eml"))
        # flip a character inside the folded b= payload (after "b=" marker)
        marker = b"b="
        pos = bytes(msg).index(b"b=") + 2
        # skip folding whitespace
        while msg[pos:pos + 1] in (b" ", b"\t", b"\r", b"\n"):
            pos += 1
        msg[pos] = ord("A") if msg[pos] != ord("A") else ord("B")
        r = dc.audit(bytes(msg), KEYRING)
        self.assertEqual(r.reason_code, dc.SIGNATURE_MISMATCH)
        self.assertEqual(r.body["verdict"], "pass")


class KeyParsingTests(unittest.TestCase):
    def test_spki_roundtrip(self):
        with open(
            os.path.join(FIX, "keys", "example.com-default.public.spki.pem")
        ) as handle:
            pem = handle.read()
        b64 = "".join(
            l for l in pem.splitlines() if not l.startswith("-----")
        )
        der = base64.b64decode(b64)
        n1, e1 = dc.parse_rsa_public_key(der)
        # Bare RSA key from keyring should yield identical parameters
        n2, e2 = dc.lookup_public_key(KEYRING, "example.com", "default")
        self.assertEqual((n1, e1), (n2, e2))
        self.assertEqual(e1, 65537)


if __name__ == "__main__":
    unittest.main(verbosity=2)
