package dkim

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func registryFor(key *rsa.PrivateKey, domain, selector string) *Registry {
	return NewRegistry(map[[2]string]*rsa.PublicKey{
		{domain, selector}: &key.PublicKey,
	})
}

const testMessage = "From: Alice <alice@example.com>\r\n" +
	"To: Bob <bob@example.net>\r\n" +
	"Subject: Hello\r\n" +
	"\r\n" +
	"Body text.\r\n"

func signTestMessage(t *testing.T, key *rsa.PrivateKey, msg string, opts SignOptions) []byte {
	t.Helper()
	if opts.Domain == "" {
		opts.Domain = "example.com"
	}
	if opts.Selector == "" {
		opts.Selector = "s1"
	}
	if len(opts.Headers) == 0 {
		opts.Headers = []string{"from", "to", "subject"}
	}
	signed, err := Sign([]byte(msg), key, opts)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func auditReasons(t *testing.T, raw []byte, reg *Registry) *Result {
	t.Helper()
	res, aerr := Audit(raw, reg)
	if aerr != nil && res == nil {
		res = FailureResult(aerr)
	}
	return res
}

func TestAuditValidAllCanonicalizations(t *testing.T) {
	key := testKey(t)
	reg := registryFor(key, "example.com", "s1")
	for _, hc := range []string{"simple", "relaxed"} {
		for _, bc := range []string{"simple", "relaxed"} {
			signed := signTestMessage(t, key, testMessage, SignOptions{HeaderCanon: hc, BodyCanon: bc, FoldB: true})
			res := auditReasons(t, signed, reg)
			if !res.Archive {
				t.Fatalf("c=%s/%s: expected archive, got %+v", hc, bc, res)
			}
			if res.Domain != "example.com" || res.Selector != "s1" {
				t.Fatalf("c=%s/%s: wrong identity %+v", hc, bc, res)
			}
			if res.Canonicalization.Header != hc || res.Canonicalization.Body != bc {
				t.Fatalf("c=%s/%s: wrong canonicalization %+v", hc, bc, res.Canonicalization)
			}
		}
	}
}

func TestAuditBodyHashMismatch(t *testing.T) {
	key := testKey(t)
	reg := registryFor(key, "example.com", "s1")
	signed := signTestMessage(t, key, testMessage, SignOptions{})
	tampered := bytes.Replace(signed, []byte("Body text."), []byte("Body text!"), 1)

	res := auditReasons(t, tampered, reg)
	if res.Archive {
		t.Fatal("tampered body must not be archived")
	}
	if res.BodyHash.Verdict != "fail" || res.BodyHash.Reason != ReasonBodyHashMismatch {
		t.Fatalf("bodyHash verdict = %+v", res.BodyHash)
	}
	// The signature covers headers only, so it still verifies: the two
	// verdicts are independent.
	if res.Signature.Verdict != "pass" {
		t.Fatalf("signature verdict = %+v, want pass", res.Signature)
	}
}

func TestAuditSignatureMismatch(t *testing.T) {
	key := testKey(t)
	reg := registryFor(key, "example.com", "s1")
	signed := signTestMessage(t, key, testMessage, SignOptions{})
	tampered := bytes.Replace(signed, []byte("Subject: Hello"), []byte("Subject: Hell0"), 1)

	res := auditReasons(t, tampered, reg)
	if res.Archive {
		t.Fatal("tampered signed header must not be archived")
	}
	if res.Signature.Verdict != "fail" || res.Signature.Reason != ReasonSignatureMismatch {
		t.Fatalf("signature verdict = %+v", res.Signature)
	}
	if res.BodyHash.Verdict != "pass" {
		t.Fatalf("bodyHash verdict = %+v, want pass", res.BodyHash)
	}
}

func TestAuditUnknownKey(t *testing.T) {
	key := testKey(t)
	reg := registryFor(key, "example.com", "s1")
	signed := signTestMessage(t, key, testMessage, SignOptions{Domain: "other.example"})

	res := auditReasons(t, signed, reg)
	if res.Archive || res.BodyHash.Reason != ReasonKeyNotFound || res.Signature.Reason != ReasonKeyNotFound {
		t.Fatalf("unknown key: %+v", res)
	}
}

func TestAuditRejectsPolicyViolations(t *testing.T) {
	key := testKey(t)
	reg := registryFor(key, "example.com", "s1")
	valid := signTestMessage(t, key, testMessage, SignOptions{})

	mutate := func(old, new string) []byte {
		t.Helper()
		out := bytes.Replace(valid, []byte(old), []byte(new), 1)
		if bytes.Equal(out, valid) {
			t.Fatalf("mutation %q -> %q did not apply", old, new)
		}
		return out
	}

	cases := []struct {
		name   string
		raw    []byte
		reason string
	}{
		{"sha1 algorithm", mutate("a=rsa-sha256", "a=rsa-sha1"), ReasonUnsupportedAlgorithm},
		{"l tag forbidden", mutate("bh=", "l=10; bh="), ReasonForbiddenBodyLengthTag},
		{"from not signed", mutate("h=from:to:subject", "h=to:subject"), ReasonFromNotSigned},
		{"unsupported canon", mutate("c=simple/simple", "c=simple/strict"), ReasonUnsupportedCanon},
		{"unsupported version", mutate("v=1", "v=2"), ReasonUnsupportedVersion},
		{"duplicate tag", mutate("s=s1", "s=s1; s=s1"), ReasonDuplicateTag},
		{"bad query method", mutate("bh=", "q=dns/whois; bh="), ReasonUnsupportedQueryMethod},
		{"identity outside domain", mutate("bh=", "i=user@evil.example; bh="), ReasonIdentityDomainMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := auditReasons(t, tc.raw, reg)
			if res.Archive {
				t.Fatal("must not archive")
			}
			if res.BodyHash.Reason != tc.reason || res.Signature.Reason != tc.reason {
				t.Fatalf("reasons = %q/%q, want %q", res.BodyHash.Reason, res.Signature.Reason, tc.reason)
			}
		})
	}
}

func TestAuditRequestShapeErrors(t *testing.T) {
	key := testKey(t)
	reg := registryFor(key, "example.com", "s1")
	valid := signTestMessage(t, key, testMessage, SignOptions{})

	t.Run("bare LF rejected", func(t *testing.T) {
		raw := bytes.Replace(valid, []byte("\r\n"), []byte("\n"), 1)
		_, aerr := Audit(raw, reg)
		if aerr == nil || aerr.Reason != ReasonInvalidLineEndings {
			t.Fatalf("aerr = %v", aerr)
		}
	})

	t.Run("bare CR rejected", func(t *testing.T) {
		raw := append(valid, '\r')
		_, aerr := Audit(raw, reg)
		if aerr == nil || aerr.Reason != ReasonInvalidLineEndings {
			t.Fatalf("aerr = %v", aerr)
		}
	})

	t.Run("oversize rejected", func(t *testing.T) {
		raw := make([]byte, MaxMessageSize+1)
		_, aerr := Audit(raw, reg)
		if aerr == nil || aerr.Reason != ReasonMessageTooLarge {
			t.Fatalf("aerr = %v", aerr)
		}
	})

	t.Run("no DKIM-Signature", func(t *testing.T) {
		_, aerr := Audit([]byte(testMessage), reg)
		if aerr == nil || aerr.Reason != ReasonNoDKIMSignature {
			t.Fatalf("aerr = %v", aerr)
		}
	})

	t.Run("multiple DKIM-Signatures", func(t *testing.T) {
		raw := append([]byte("DKIM-Signature: v=1; a=rsa-sha256; d=x; s=y\r\n"), valid...)
		_, aerr := Audit(raw, reg)
		if aerr == nil || aerr.Reason != ReasonMultipleDKIMSignatures {
			t.Fatalf("aerr = %v", aerr)
		}
	})

	t.Run("missing body separator", func(t *testing.T) {
		_, aerr := Audit([]byte("From: a@b.c\r\nSubject: x\r\n"), reg)
		if aerr == nil || aerr.Reason != ReasonMalformedMessage {
			t.Fatalf("aerr = %v", aerr)
		}
	})
}

func TestAuditDuplicateHeaderCoverage(t *testing.T) {
	key := testKey(t)
	reg := registryFor(key, "example.com", "s1")

	msg := "From: Alice <alice@example.com>\r\n" +
		"From: Alice <alice@example.com>\r\n" +
		"Subject: dup\r\n" +
		"\r\n" +
		"Body.\r\n"

	t.Run("fully signed duplicates pass", func(t *testing.T) {
		signed := signTestMessage(t, key, msg, SignOptions{Headers: []string{"from", "from", "subject"}})
		res := auditReasons(t, signed, reg)
		if !res.Archive {
			t.Fatalf("expected archive, got %+v", res)
		}
	})

	t.Run("partially signed duplicates rejected", func(t *testing.T) {
		signed := signTestMessage(t, key, msg, SignOptions{Headers: []string{"from", "subject"}})
		res := auditReasons(t, signed, reg)
		if res.Archive || res.Signature.Reason != ReasonHeaderInstancesNotFullySigned {
			t.Fatalf("expected coverage rejection, got %+v", res)
		}
	})

	t.Run("stacked unsigned duplicate rejected", func(t *testing.T) {
		single := "From: Alice <alice@example.com>\r\nSubject: dup\r\n\r\nBody.\r\n"
		signed := signTestMessage(t, key, single, SignOptions{Headers: []string{"from", "subject"}})
		// An upstream stacks a second From on top after signing.
		end := bytes.Index(signed, []byte("\r\n"))
		stacked := append(signed[:end+2:end+2], append([]byte("From: Mallory <m@example.org>\r\n"), signed[end+2:]...)...)
		res := auditReasons(t, stacked, reg)
		if res.Archive || res.Signature.Reason != ReasonHeaderInstancesNotFullySigned {
			t.Fatalf("expected coverage rejection, got %+v", res)
		}
	})
}

func TestBottomUpSelection(t *testing.T) {
	key := testKey(t)
	reg := registryFor(key, "example.com", "s1")

	// Two distinct X-Tag values; h signs both. Swapping their order after
	// signing must break the signature, proving selection order matters.
	msg := "From: a@example.com\r\nX-Tag: top\r\nX-Tag: bottom\r\n\r\nB.\r\n"
	signed := signTestMessage(t, key, msg, SignOptions{Headers: []string{"from", "x-tag", "x-tag"}})
	if res := auditReasons(t, signed, reg); !res.Archive {
		t.Fatalf("expected archive, got %+v", res)
	}
	swapped := bytes.Replace(signed, []byte("X-Tag: top\r\nX-Tag: bottom"), []byte("X-Tag: bottom\r\nX-Tag: top"), 1)
	res := auditReasons(t, swapped, reg)
	if res.Signature.Verdict != "fail" {
		t.Fatalf("expected signature failure after swap, got %+v", res)
	}
}

func TestFoldedSignatureHeader(t *testing.T) {
	key := testKey(t)
	reg := registryFor(key, "example.com", "s1")
	for _, hc := range []string{"simple", "relaxed"} {
		signed := signTestMessage(t, key, testMessage, SignOptions{HeaderCanon: hc, FoldB: true})
		if !bytes.Contains(signed, []byte("b=\r\n\t")) {
			t.Fatalf("c=%s: fixture is not folded", hc)
		}
		if res := auditReasons(t, signed, reg); !res.Archive {
			t.Fatalf("c=%s: folded b= must verify, got %+v", hc, res)
		}
	}
}

func TestCanonicalizeBodySimple(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "\r\n"},
		{"\r\n", "\r\n"},
		{"\r\n\r\n\r\n", "\r\n"},
		{"abc", "abc\r\n"},
		{"abc\r\n", "abc\r\n"},
		{"abc\r\n\r\n\r\n", "abc\r\n"},
		{"abc\r\n\r\ndef\r\n\r\n", "abc\r\n\r\ndef\r\n"},
	}
	for _, tc := range cases {
		if got := CanonicalizeBody([]byte(tc.in), "simple"); string(got) != tc.want {
			t.Errorf("simple(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCanonicalizeBodyRelaxed(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"\r\n", ""},
		{"\r\n\r\n", ""},
		{"abc", "abc\r\n"},
		{"abc\r\n\r\n\r\n", "abc\r\n"},
		{"a  b\t\tc \r\n", "a b c\r\n"},
		{"  lead\r\n", " lead\r\n"},
		{" \t \r\n", ""},
		{"x\r\n \r\ny\r\n", "x\r\n\r\ny\r\n"},
	}
	for _, tc := range cases {
		if got := CanonicalizeBody([]byte(tc.in), "relaxed"); string(got) != tc.want {
			t.Errorf("relaxed(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCanonicalizeHeaderRelaxed(t *testing.T) {
	field := &HeaderField{Name: "SubJECT", Raw: []byte("SubJECT:  Hello \r\n\t World\t ")}
	if got := CanonicalizeHeader(field, "relaxed"); string(got) != "subject:Hello World" {
		t.Errorf("relaxed header = %q", got)
	}
	field = &HeaderField{Name: "X-A", Raw: []byte("X-A :  spaced  ")}
	if got := CanonicalizeHeader(field, "relaxed"); string(got) != "x-a:spaced" {
		t.Errorf("relaxed header = %q", got)
	}
}

func TestCanonicalizeHeaderSimple(t *testing.T) {
	raw := []byte("X-A:  folded\r\n\tvalue")
	field := &HeaderField{Name: "X-A", Raw: raw}
	got := CanonicalizeHeader(field, "simple")
	if !bytes.Equal(got, append(raw, '\r', '\n')) {
		t.Errorf("simple header must be byte-identical plus CRLF, got %q", got)
	}
}

func TestStripSignatureValue(t *testing.T) {
	field := &HeaderField{Name: "DKIM-Signature", Raw: []byte(
		"DKIM-Signature: v=1; a=rsa-sha256;\r\n\tb=abc\r\n\tdef; bh=xyz")}
	stripped := StripSignatureValue(field)
	want := "DKIM-Signature: v=1; a=rsa-sha256;\r\n\tb=; bh=xyz"
	if string(stripped.Raw) != want {
		t.Errorf("stripped = %q, want %q", stripped.Raw, want)
	}

	// b= as the final tag, with WSP around '='.
	field = &HeaderField{Name: "DKIM-Signature", Raw: []byte("DKIM-Signature: v=1; b = zzz")}
	if got := string(StripSignatureValue(field).Raw); got != "DKIM-Signature: v=1; b =" {
		t.Errorf("stripped = %q", got)
	}
}

func TestParseSignatureDefaults(t *testing.T) {
	field := &HeaderField{Name: "DKIM-Signature", Raw: []byte(
		"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=s1; h=from; " +
			"bh=" + strings.Repeat("A", 43) + "=; b=QUJD")}
	sig, aerr := ParseSignature(field)
	if aerr != nil {
		t.Fatalf("parse: %v", aerr)
	}
	if sig.HeaderCanon != "simple" || sig.BodyCanon != "simple" {
		t.Errorf("default canonicalization = %s/%s", sig.HeaderCanon, sig.BodyCanon)
	}
}
