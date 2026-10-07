package dkim

import (
	"encoding/base64"
	"net/http"
	"strings"
)

// Signature is the parsed and policy-validated DKIM-Signature header field.
type Signature struct {
	Tags        map[string]string
	Domain      string
	Selector    string
	HeaderCanon string
	BodyCanon   string
	HList       []string // lowercased header field names, in signing order
	BodyHash    []byte   // decoded bh= value
	Sig         []byte   // decoded b= value
	Field       *HeaderField
}

func isTagName(s string) bool {
	if s == "" || !isAlpha(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !isAlpha(c) && !isDigit(c) && c != '_' {
			return false
		}
	}
	return true
}

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isFieldName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 33 || s[i] > 126 || s[i] == ':' {
			return false
		}
	}
	return true
}

func trimWSP(s string) string {
	return strings.Trim(s, " \t")
}

func stripAllWSP(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, s)
}

func decodeBase64Tag(name, v string) ([]byte, *AuditError) {
	b, err := base64.StdEncoding.DecodeString(stripAllWSP(v))
	if err != nil {
		return nil, errf(ReasonInvalidTagValue, name+"= is not valid base64", http.StatusOK)
	}
	return b, nil
}

// ParseSignature parses the DKIM-Signature tag-value list and enforces the
// archival policy: rsa-sha256 only, simple/relaxed canonicalization only, no
// l= tag, and h= must cover From. All failures use HTTP 200 because the
// request itself was well formed; the message simply fails the audit.
func ParseSignature(f *HeaderField) (*Signature, *AuditError) {
	fail := func(reason, detail string) *AuditError {
		return errf(reason, detail, http.StatusOK)
	}

	tags := make(map[string]string)
	for _, part := range strings.Split(string(f.UnfoldedValue()), ";") {
		part = trimWSP(part)
		if part == "" {
			continue
		}
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			return nil, fail(ReasonMalformedDKIMSignature, "tag without '=' separator")
		}
		name := trimWSP(part[:eq])
		value := trimWSP(part[eq+1:])
		if !isTagName(name) {
			return nil, fail(ReasonMalformedDKIMSignature, "invalid tag name "+strconv_(name))
		}
		if _, dup := tags[name]; dup {
			return nil, fail(ReasonDuplicateTag, "duplicate "+name+"= tag")
		}
		tags[name] = value
	}

	sig := &Signature{Tags: tags, Field: f}

	if v, ok := tags["v"]; ok && v != "1" {
		return nil, fail(ReasonUnsupportedVersion, "unsupported DKIM version "+strconv_(v))
	}

	a, ok := tags["a"]
	if !ok || a == "" {
		return nil, fail(ReasonMissingTag, "missing a= tag")
	}
	if strings.ToLower(a) != "rsa-sha256" {
		return nil, fail(ReasonUnsupportedAlgorithm, "a="+a+" is not rsa-sha256")
	}

	c := "simple/simple"
	if v, ok := tags["c"]; ok {
		c = strings.ToLower(v)
	}
	headerCanon, bodyCanon := "simple", "simple"
	switch parts := strings.Split(c, "/"); {
	case len(parts) == 1 && isCanonMode(parts[0]):
		headerCanon, bodyCanon = parts[0], "simple"
	case len(parts) == 2 && isCanonMode(parts[0]) && isCanonMode(parts[1]):
		headerCanon, bodyCanon = parts[0], parts[1]
	default:
		return nil, fail(ReasonUnsupportedCanon, "c="+c+" is not simple or relaxed")
	}
	sig.HeaderCanon, sig.BodyCanon = headerCanon, bodyCanon

	if _, ok := tags["l"]; ok {
		return nil, fail(ReasonForbiddenBodyLengthTag, "l= body length tag is not accepted for archival")
	}

	if q, ok := tags["q"]; ok && strings.ToLower(q) != "dns/txt" {
		return nil, fail(ReasonUnsupportedQueryMethod, "q="+q+" is not dns/txt")
	}

	for _, required := range []string{"d", "s", "h", "bh", "b"} {
		if v, ok := tags[required]; !ok || v == "" {
			return nil, fail(ReasonMissingTag, "missing "+required+"= tag")
		}
	}
	sig.Domain = tags["d"]
	sig.Selector = tags["s"]

	for _, name := range strings.Split(tags["h"], ":") {
		name = strings.ToLower(trimWSP(name))
		if !isFieldName(name) {
			return nil, fail(ReasonInvalidTagValue, "invalid header field name in h= tag")
		}
		if name == "dkim-signature" {
			return nil, fail(ReasonInvalidTagValue, "h= must not list dkim-signature")
		}
		sig.HList = append(sig.HList, name)
	}
	fromCovered := false
	for _, name := range sig.HList {
		if name == "from" {
			fromCovered = true
			break
		}
	}
	if !fromCovered {
		return nil, fail(ReasonFromNotSigned, "h= tag does not cover the From header field")
	}

	if i, ok := tags["i"]; ok && i != "" {
		at := strings.LastIndexByte(i, '@')
		idDomain := ""
		if at >= 0 {
			idDomain = i[at+1:]
		}
		d := strings.ToLower(sig.Domain)
		idDomain = strings.ToLower(idDomain)
		if idDomain != d && !strings.HasSuffix(idDomain, "."+d) {
			return nil, fail(ReasonIdentityDomainMismatch, "i= identity is outside the d= domain")
		}
	}

	bh, aerr := decodeBase64Tag("bh", tags["bh"])
	if aerr != nil {
		return nil, aerr
	}
	if len(bh) != 32 {
		return nil, fail(ReasonInvalidTagValue, "bh= is not a SHA-256 digest")
	}
	sig.BodyHash = bh

	b, aerr := decodeBase64Tag("b", tags["b"])
	if aerr != nil {
		return nil, aerr
	}
	if len(b) == 0 {
		return nil, fail(ReasonMissingTag, "empty b= tag")
	}
	sig.Sig = b

	return sig, nil
}

func isCanonMode(s string) bool { return s == "simple" || s == "relaxed" }

func strconv_(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return "'" + s + "'"
}
