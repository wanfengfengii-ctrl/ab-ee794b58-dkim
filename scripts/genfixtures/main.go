// Command genfixtures regenerates the smoke-test fixtures: a fresh RSA key
// pair, the key registry consumed by the API (keys/keys.json), and the
// signed sample messages under fixtures/. Run once and commit the output;
// re-running rotates the fixture key, which is safe because fixtures and
// registry are regenerated together.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"dkim-audit/internal/dkim"
)

const (
	fixtureDomain   = "example.com"
	fixtureSelector = "s1"
)

func main() {
	root, err := os.Getwd()
	must(err)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)

	base := baseMessage()

	hList := []string{"from", "to", "subject", "date", "message-id", "x-custom", "x-custom"}
	valid, err := dkim.Sign(base, key, dkim.SignOptions{
		Domain:      fixtureDomain,
		Selector:    fixtureSelector,
		HeaderCanon: "relaxed",
		BodyCanon:   "simple",
		Headers:     hList,
		FoldB:       true,
	})
	must(err)

	// Body rewritten after signing: the body hash must fail while the
	// header-only signature still verifies.
	bodyRewritten := bytes.Replace(valid, []byte("Body line one."), []byte("Body line ONE."), 1)
	if bytes.Equal(bodyRewritten, valid) {
		log.Fatal("body rewrite did not change the message")
	}

	// A forwarding component stacked an unsigned, same-named From field on
	// top. Cryptographically the bottom-up selection still finds the signed
	// From, but the archival policy must refuse it.
	dup := injectHeaderAfterSignature(valid, "From: Mallory <mallory@example.org>\r\n")

	unknownKey, err := dkim.Sign(base, key, dkim.SignOptions{
		Domain:      "unknown.example",
		Selector:    fixtureSelector,
		HeaderCanon: "relaxed",
		BodyCanon:   "simple",
		Headers:     hList,
	})
	must(err)

	withLTag, err := dkim.Sign(base, key, dkim.SignOptions{
		Domain:      fixtureDomain,
		Selector:    fixtureSelector,
		HeaderCanon: "relaxed",
		BodyCanon:   "simple",
		Headers:     hList,
		WithBodyLen: true,
	})
	must(err)

	writeFile(filepath.Join(root, "fixtures", "valid.eml"), valid)
	writeFile(filepath.Join(root, "fixtures", "body-rewritten.eml"), bodyRewritten)
	writeFile(filepath.Join(root, "fixtures", "duplicate-header.eml"), dup)
	writeFile(filepath.Join(root, "fixtures", "unknown-key.eml"), unknownKey)
	writeFile(filepath.Join(root, "fixtures", "l-tag.eml"), withLTag)

	writeJSON(filepath.Join(root, "keys", "keys.json"), map[string]any{
		"keys": []map[string]string{{
			"domain":    fixtureDomain,
			"selector":  fixtureSelector,
			"algorithm": "rsa-sha256",
			"publicKey": publicKeyPEM(&key.PublicKey),
		}},
	})

	writeJSON(filepath.Join(root, "fixtures", "cases.json"), []map[string]any{
		{
			"name": "valid signature archives",
			"file": "valid.eml", "status": 200, "archive": true,
			"bodyVerdict": "pass", "bodyReason": "OK",
			"signatureVerdict": "pass", "signatureReason": "OK",
		},
		{
			"name": "rewritten body rejected",
			"file": "body-rewritten.eml", "status": 200, "archive": false,
			"bodyVerdict": "fail", "bodyReason": "BODY_HASH_MISMATCH",
			"signatureVerdict": "pass", "signatureReason": "OK",
		},
		{
			"name": "stacked duplicate From rejected",
			"file": "duplicate-header.eml", "status": 200, "archive": false,
			"bodyVerdict": "fail", "bodyReason": "ERR_HEADER_INSTANCES_NOT_FULLY_SIGNED",
			"signatureVerdict": "fail", "signatureReason": "ERR_HEADER_INSTANCES_NOT_FULLY_SIGNED",
		},
		{
			"name": "unknown key rejected",
			"file": "unknown-key.eml", "status": 200, "archive": false,
			"bodyVerdict": "fail", "bodyReason": "ERR_KEY_NOT_FOUND",
			"signatureVerdict": "fail", "signatureReason": "ERR_KEY_NOT_FOUND",
		},
		{
			"name": "l= tag rejected",
			"file": "l-tag.eml", "status": 200, "archive": false,
			"bodyVerdict": "fail", "bodyReason": "ERR_FORBIDDEN_BODY_LENGTH_TAG",
			"signatureVerdict": "fail", "signatureReason": "ERR_FORBIDDEN_BODY_LENGTH_TAG",
		},
	})

	fmt.Println("fixtures and keys/keys.json regenerated")
}

// baseMessage returns the unsigned sample message. It exercises folded
// headers, duplicated X-Custom fields, trailing whitespace in the body, and
// trailing empty lines.
func baseMessage() []byte {
	return []byte("From: Alice <alice@example.com>\r\n" +
		"To: Bob <bob@example.net>\r\n" +
		"Subject: Forensic archive\r\n" +
		"\tintake report 2026\r\n" +
		"Date: Tue, 07 Oct 2026 09:00:00 +0000\r\n" +
		"Message-ID: <m1@example.com>\r\n" +
		"X-Custom: one\r\n" +
		"X-Custom: two\r\n" +
		"\r\n" +
		"Body line one.\r\n" +
		"Body line two.\r\n" +
		"\r\n")
}

// injectHeaderAfterSignature inserts extra immediately after the first
// (DKIM-Signature) header field, i.e. on top of the original header block.
// The first field may be folded, so its continuation lines are skipped.
func injectHeaderAfterSignature(msg []byte, extra string) []byte {
	pos := 0
	for {
		end := bytes.Index(msg[pos:], []byte("\r\n"))
		if end < 0 {
			log.Fatal("fixture message has no header line")
		}
		pos += end + 2
		if pos >= len(msg) || (msg[pos] != ' ' && msg[pos] != '\t') {
			break
		}
	}
	out := make([]byte, 0, len(msg)+len(extra))
	out = append(out, msg[:pos]...)
	out = append(out, extra...)
	return append(out, msg[pos:]...)
}

func publicKeyPEM(pub *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	must(err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func writeFile(path string, data []byte) {
	must(os.MkdirAll(filepath.Dir(path), 0o755))
	must(os.WriteFile(path, data, 0o644))
}

func writeJSON(path string, v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	must(err)
	writeFile(path, append(data, '\n'))
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
