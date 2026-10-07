package dkim

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
)

// SignOptions configures Sign. It exists to produce test fixtures and unit
// test vectors; the audit path never signs.
type SignOptions struct {
	Domain      string
	Selector    string
	HeaderCanon string   // "simple" or "relaxed" (default simple)
	BodyCanon   string   // "simple" or "relaxed" (default simple)
	Headers     []string // h= list, in order; duplicates sign repeated fields
	WithBodyLen bool     // emit an l= tag (policy-forbidden; negative fixtures)
	FoldB       bool     // fold the b= value across continuation lines
}

// Sign produces a DKIM-signed message by prepending a DKIM-Signature header
// field to msg, which must already use CRLF line endings.
func Sign(msg []byte, key *rsa.PrivateKey, opts SignOptions) ([]byte, error) {
	m, aerr := ParseMessage(msg)
	if aerr != nil {
		return nil, aerr
	}
	headerCanon := opts.HeaderCanon
	if headerCanon == "" {
		headerCanon = "simple"
	}
	bodyCanon := opts.BodyCanon
	if bodyCanon == "" {
		bodyCanon = "simple"
	}

	canonBody := CanonicalizeBody(m.Body, bodyCanon)
	bh := base64.StdEncoding.EncodeToString(sha256sum(canonBody))

	var tags strings.Builder
	tags.WriteString("v=1; a=rsa-sha256; c=")
	tags.WriteString(headerCanon + "/" + bodyCanon)
	tags.WriteString("; d=" + opts.Domain + "; s=" + opts.Selector)
	tags.WriteString("; h=" + strings.Join(opts.Headers, ":"))
	if opts.WithBodyLen {
		tags.WriteString("; l=" + strconv.Itoa(len(canonBody)))
	}
	tags.WriteString("; bh=" + bh + "; b=")

	unsigned := &HeaderField{Name: "DKIM-Signature", Raw: []byte("DKIM-Signature: " + tags.String())}

	sig := &Signature{
		HeaderCanon: headerCanon,
		BodyCanon:   bodyCanon,
		HList:       lowerAll(opts.Headers),
		Field:       unsigned,
	}
	digest := sha256.Sum256(headerHashInput(m, sig))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return nil, err
	}

	b64 := base64.StdEncoding.EncodeToString(sigBytes)
	headerValue := tags.String()
	if opts.FoldB {
		headerValue += foldBase64(b64)
	} else {
		headerValue += b64
	}

	out := make([]byte, 0, len(msg)+len(headerValue)+24)
	out = append(out, "DKIM-Signature: "...)
	out = append(out, headerValue...)
	out = append(out, '\r', '\n')
	return append(out, msg...), nil
}

// foldBase64 wraps base64 data onto continuation lines. The wrapping lives
// entirely inside the b= value, so removing the value restores the exact
// pre-image that was hashed.
func foldBase64(s string) string {
	var b strings.Builder
	for len(s) > 56 {
		b.WriteString("\r\n\t")
		b.WriteString(s[:56])
		s = s[56:]
	}
	b.WriteString("\r\n\t")
	b.WriteString(s)
	return b.String()
}

func lowerAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

func sha256sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
