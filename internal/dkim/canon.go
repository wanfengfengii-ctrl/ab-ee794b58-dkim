package dkim

import (
	"bytes"
)

// CanonicalizeBody implements the simple and relaxed body canonicalization
// algorithms of RFC 6376 §3.4.3/§3.4.4, including the trailing-empty-line
// rules: simple maps an empty body to a single CRLF, relaxed to nothing.
func CanonicalizeBody(body []byte, mode string) []byte {
	if mode == "relaxed" {
		return canonicalizeBodyRelaxed(body)
	}
	return canonicalizeBodySimple(body)
}

func canonicalizeBodySimple(body []byte) []byte {
	// Ignore all empty lines at the end of the body, then terminate the
	// (possibly now empty) body with a single CRLF.
	for len(body) >= 2 && body[len(body)-2] == '\r' && body[len(body)-1] == '\n' {
		body = body[:len(body)-2]
	}
	out := make([]byte, 0, len(body)+2)
	out = append(out, body...)
	return append(out, '\r', '\n')
}

func canonicalizeBodyRelaxed(body []byte) []byte {
	lines := bytes.Split(body, []byte("\r\n"))
	canon := make([][]byte, 0, len(lines))
	for _, line := range lines {
		canon = append(canon, relaxBodyLine(line))
	}
	// Ignore all empty lines at the end of the body.
	for len(canon) > 0 && len(canon[len(canon)-1]) == 0 {
		canon = canon[:len(canon)-1]
	}
	if len(canon) == 0 {
		return nil
	}
	var out []byte
	for _, line := range canon {
		out = append(out, line...)
		out = append(out, '\r', '\n')
	}
	return out
}

// relaxBodyLine compresses every WSP run to a single SP and drops trailing
// WSP. Leading WSP is compressed but kept, per RFC 6376 §3.4.4.
func relaxBodyLine(line []byte) []byte {
	out := compressWSP(line)
	if n := len(out); n > 0 && out[n-1] == ' ' {
		out = out[:n-1]
	}
	return out
}

// compressWSP replaces every run of SP/TAB with a single SP.
func compressWSP(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); {
		if b[i] == ' ' || b[i] == '\t' {
			for i < len(b) && (b[i] == ' ' || b[i] == '\t') {
				i++
			}
			out = append(out, ' ')
			continue
		}
		out = append(out, b[i])
		i++
	}
	return out
}

// CanonicalizeHeader implements the simple and relaxed header
// canonicalization algorithms of RFC 6376 §3.4.1/§3.4.2. Simple output keeps
// the field exactly as received and includes the trailing CRLF; relaxed
// output lowercases the field name, unfolds and compresses WSP, and has no
// trailing CRLF.
func CanonicalizeHeader(f *HeaderField, mode string) []byte {
	if mode == "relaxed" {
		return canonicalizeHeaderRelaxed(f)
	}
	out := make([]byte, 0, len(f.Raw)+2)
	out = append(out, f.Raw...)
	return append(out, '\r', '\n')
}

func canonicalizeHeaderRelaxed(f *HeaderField) []byte {
	colon := bytes.IndexByte(f.Raw, ':')
	name := bytes.ToLower(bytes.Trim(f.Raw[:colon], " \t"))
	value := compressWSP(unfold(f.Raw[colon+1:]))
	value = bytes.Trim(value, " ")
	out := make([]byte, 0, len(name)+1+len(value))
	out = append(out, name...)
	out = append(out, ':')
	return append(out, value...)
}

// StripSignatureValue returns a copy of the DKIM-Signature field with the b=
// tag value removed, as required before canonicalizing it for the header
// hash. Folding of the remaining tags is preserved byte-for-byte.
func StripSignatureValue(f *HeaderField) *HeaderField {
	colon := bytes.IndexByte(f.Raw, ':')
	value := removeBValue(f.Raw[colon+1:])
	raw := make([]byte, 0, colon+1+len(value))
	raw = append(raw, f.Raw[:colon+1]...)
	raw = append(raw, value...)
	return &HeaderField{Name: f.Name, Raw: raw}
}

// removeBValue deletes the value of the b= tag from a raw (possibly folded)
// DKIM-Signature header value, keeping "b=" itself and every other tag
// byte-for-byte identical.
func removeBValue(v []byte) []byte {
	for segStart := 0; segStart <= len(v); {
		segEnd := len(v)
		if i := bytes.IndexByte(v[segStart:], ';'); i >= 0 {
			segEnd = segStart + i
		}
		if eq, ok := tagEqualsOffset(v[segStart:segEnd], "b"); ok {
			out := make([]byte, 0, len(v)-(segEnd-(segStart+eq+1)))
			out = append(out, v[:segStart+eq+1]...)
			return append(out, v[segEnd:]...)
		}
		if segEnd == len(v) {
			break
		}
		segStart = segEnd + 1
	}
	return v
}

// tagEqualsOffset reports whether the segment "name = ..." (WSP and folding
// permitted) belongs to the given tag, returning the offset of '='.
func tagEqualsOffset(seg []byte, want string) (int, bool) {
	i := 0
	for i < len(seg) && isFWS(seg[i]) {
		i++
	}
	start := i
	for i < len(seg) && (isAlpha(seg[i]) || isDigit(seg[i]) || seg[i] == '_') {
		i++
	}
	name := seg[start:i]
	for i < len(seg) && isFWS(seg[i]) {
		i++
	}
	if i >= len(seg) || seg[i] != '=' {
		return 0, false
	}
	if len(name) != len(want) {
		return 0, false
	}
	for j := range want {
		c := name[j]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != want[j] {
			return 0, false
		}
	}
	return i, true
}

func isFWS(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

// selectSignedFields implements the bottom-up selection of RFC 6376 §5.4.2:
// for each name in hList (in order) the bottom-most not-yet-selected instance
// of that header field is chosen. Names with no remaining instance are
// skipped.
func selectSignedFields(fields []HeaderField, hList []string) []*HeaderField {
	used := make([]bool, len(fields))
	out := make([]*HeaderField, 0, len(hList))
	for _, name := range hList {
		for i := len(fields) - 1; i >= 0; i-- {
			if used[i] || !equalFoldASCII(fields[i].Name, name) {
				continue
			}
			used[i] = true
			out = append(out, &fields[i])
			break
		}
	}
	return out
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
