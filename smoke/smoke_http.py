"""End-to-end HTTP smoke checks against POST /api/dkim/audit.

Exercises exactly the scenarios the archiving gateway cares about:
  * a legitimately signed mail is accepted
  * a rewritten body is rejected with BODY_HASH_MISMATCH (while the header
    signature independently still verifies)
  * duplicate header fields follow bottom-up selection
    (top mutation passes, bottom mutation fails signature)
  * framing / policy rejections stay distinguishable
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

FIX = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..",
    "tests",
    "fixtures",
)


class CheckFailure(AssertionError):
    pass


def post(base_url: str, raw: bytes, content_type: str = "application/rfc822"):
    req = urllib.request.Request(
        base_url + "/api/dkim/audit",
        data=raw,
        method="POST",
        headers={"Content-Type": content_type},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def read_fixture(name: str) -> bytes:
    with open(os.path.join(FIX, name), "rb") as handle:
        return handle.read()


def expect(cond: bool, label: str, detail: str = "") -> None:
    if not cond:
        raise CheckFailure(f"{label}: {detail}")


def run(base_url: str) -> int:
    failures = []
    checks = 0

    def check(name: str, fn) -> None:
        nonlocal checks
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            failures.append((name, str(exc)))
            print(f"  [FAIL] {name}: {exc}")
        else:
            checks += 1
            print(f"  [ OK ] {name}")

    # 1) valid relaxed mail ------------------------------------------------
    def valid():
        status, body = post(base_url, read_fixture("valid_relaxed.eml"))
        expect(status == 200, "http 200", f"got {status}")
        expect(body["decision"] == "accept", "decision accept", str(body))
        expect(body["reason_code"] == "OK", "reason OK", body["reason_code"])
        expect(body["domain"] == "example.com", "domain echoed", str(body))
        expect(body["selector"] == "default", "selector echoed", str(body))
        expect(body["algorithm"] == "rsa-sha256", "algorithm", str(body))
        expect(
            body["canonicalization"]
            == {"headers": "relaxed", "body": "relaxed"},
            "canon modes",
            str(body["canonicalization"]),
        )
        expect(body["body_verdict"]["verdict"] == "pass", "bh pass", str(body))
        expect(body["signature_verdict"] == "pass", "sig pass", str(body))
        expect("from" in body["signed_headers"], "from covered", str(body))
    check("valid email accepted", valid)

    # 2) valid simple/simple mail -----------------------------------------
    def simple():
        status, body = post(base_url, read_fixture("valid_simple.eml"))
        expect(status == 200, "http 200", f"got {status}")
        expect(body["reason_code"] == "OK", "reason OK", str(body))
        expect(
            body["canonicalization"]
            == {"headers": "simple", "body": "simple"},
            "simple modes",
            str(body),
        )
    check("simple/simple email accepted", simple)

    # 3) rewritten body -> BODY_HASH_MISMATCH, sig independently passes ----
    def rewritten():
        status, body = post(base_url, read_fixture("body_rewritten.eml"))
        expect(status == 422, "http 422", f"got {status}")
        expect(body["decision"] == "reject", "reject", str(body))
        expect(
            body["reason_code"] == "BODY_HASH_MISMATCH",
            "stable reason",
            body["reason_code"],
        )
        expect(body["body_verdict"]["verdict"] == "fail", "bh fail", str(body))
        expect(
            body["body_verdict"]["declared_bh"]
            != body["body_verdict"]["computed"],
            "distinct digests reported",
            str(body),
        )
        expect(
            body["signature_verdict"] == "pass",
            "signature verdict independent (still pass)",
            str(body),
        )
    check("body rewrite rejected (BODY_HASH_MISMATCH)", rewritten)

    # 4a) duplicate headers, bottom occurrence signed ----------------------
    def dup_valid():
        status, body = post(
            base_url, read_fixture("duplicate_headers_valid.eml")
        )
        expect(status == 200, "http 200", f"got {status}")
        expect(body["reason_code"] == "OK", "accept", str(body))
    check("duplicate headers valid", dup_valid)

    # 4b) mutating the unsigned top occurrence must still pass -------------
    def dup_top():
        status, body = post(
            base_url, read_fixture("duplicate_headers_top_mutated.eml")
        )
        expect(status == 200, "http 200", f"got {status}")
        expect(
            body["reason_code"] == "OK",
            "top duplicate is not covered by signature",
            str(body),
        )
    check("duplicate headers: unsigned top mutation accepted", dup_top)

    # 4c) mutating the signed bottom occurrence fails the signature --------
    def dup_bottom():
        status, body = post(
            base_url, read_fixture("duplicate_headers_bottom_mutated.eml")
        )
        expect(status == 422, "http 422", f"got {status}")
        expect(
            body["reason_code"] == "SIGNATURE_MISMATCH",
            "SIGNATURE_MISMATCH",
            body["reason_code"],
        )
        expect(body["body_verdict"]["verdict"] == "pass", "bh still pass", str(body))
        expect(body["signature_verdict"] == "fail", "sig fail", str(body))
    check("duplicate headers: signed bottom mutation rejected", dup_bottom)

    # 5) l= tag forbidden --------------------------------------------------
    def l_tag():
        msg = (
            b"From: a@example.com\r\n"
            b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n"
            b" d=example.com; s=default; h=from; l=9;\r\n"
            b" bh=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=; b=AAAA\r\n"
            b"\r\nbody-here\r\n"
        )
        status, body = post(base_url, msg)
        expect(status == 400, "http 400", f"got {status}")
        expect(
            body["reason_code"] == "L_TAG_FORBIDDEN",
            "L_TAG_FORBIDDEN",
            body["reason_code"],
        )
    check("l= tag rejected (L_TAG_FORBIDDEN)", l_tag)

    # 6) unknown signing domain -------------------------------------------
    def unknown_key():
        msg = (
            b"From: a@example.com\r\n"
            b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n"
            b" d=unsigned.example; s=default; h=from;\r\n"
            b" bh=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=; b=AAAA\r\n"
            b"\r\nbody\r\n"
        )
        status, body = post(base_url, msg)
        expect(status == 404, "http 404", f"got {status}")
        expect(
            body["reason_code"] == "UNKNOWN_KEY", "UNKNOWN_KEY", body["reason_code"]
        )
    check("unknown key rejected (UNKNOWN_KEY)", unknown_key)

    # 7) bare LF framing rejected -----------------------------------------
    def framing():
        status, body = post(base_url, b"From: a@example.com\n\nbody\n")
        expect(status == 400, "http 400", f"got {status}")
        expect(
            body["reason_code"] == "MALFORMED_MESSAGE",
            "MALFORMED_MESSAGE",
            body["reason_code"],
        )
    check("bare-LF message rejected (MALFORMED_MESSAGE)", framing)

    # 8) wrong content type ------------------------------------------------
    def ctype():
        status, body = post(base_url, b"x", content_type="text/plain")
        expect(status == 415, "http 415", f"got {status}")
    check("non-rfc822 content type rejected (415)", ctype)

    # 9) oversize message --------------------------------------------------
    def oversize():
        big = b"From: a@example.com\r\n\r\n" + b"x" * (2 * 1024 * 1024 + 1)
        status, body = post(base_url, big)
        expect(status == 413, "http 413", f"got {status}")
    check("oversize message rejected (413)", oversize)

    print(f"\nsmoke: {checks} passed, {len(failures)} failed")
    return 1 if failures else 0


def main() -> int:
    base_url = os.environ.get("DKIM_API_URL", "http://127.0.0.1:8080").rstrip("/")
    print(f"HTTP smoke against {base_url}")
    return run(base_url)


if __name__ == "__main__":
    raise SystemExit(main())
