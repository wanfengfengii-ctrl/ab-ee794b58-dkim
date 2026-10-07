package dkim

import (
	"bytes"
	"net/http"
)

// MaxMessageSize is the largest raw message the audit endpoint accepts
// (2 MiB, per the service contract).
const MaxMessageSize = 2 << 20

// HeaderField is a single header field as received. Raw holds the complete
// field (name, colon, value, any folding) without the terminating CRLF.
type HeaderField struct {
	Name string
	Raw  []byte
}

// value returns the raw (still folded) field value after the colon.
func (f *HeaderField) value() []byte {
	i := bytes.IndexByte(f.Raw, ':')
	if i < 0 {
		return nil
	}
	return f.Raw[i+1:]
}

// unfold removes RFC 5322 folding (CRLF immediately followed by WSP) from b.
func unfold(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == '\r' && i+2 < len(b) && b[i+1] == '\n' && (b[i+2] == ' ' || b[i+2] == '\t') {
			i++ // skip CR; the LF is skipped on the next iteration
			continue
		}
		out = append(out, b[i])
	}
	return out
}

// UnfoldedValue returns the field value with folding removed.
func (f *HeaderField) UnfoldedValue() []byte {
	return unfold(f.value())
}

// Message is a parsed RFC 5322 message.
type Message struct {
	Fields []HeaderField
	Body   []byte // raw bytes after the empty line separating header and body
}

// validateLineEndings requires every line boundary to be CRLF. Bare LF or
// bare CR bytes are rejected so that canonicalization is unambiguous.
func validateLineEndings(raw []byte) *AuditError {
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '\r':
			if i+1 >= len(raw) || raw[i+1] != '\n' {
				return errf(ReasonInvalidLineEndings, "bare CR not followed by LF", http.StatusBadRequest)
			}
			i++ // consume the paired LF
		case '\n':
			return errf(ReasonInvalidLineEndings, "bare LF without preceding CR", http.StatusBadRequest)
		}
	}
	return nil
}

// ParseMessage validates line endings, splits header and body, and parses the
// header fields while preserving their raw bytes for canonicalization.
func ParseMessage(raw []byte) (*Message, *AuditError) {
	if len(raw) > MaxMessageSize {
		return nil, errf(ReasonMessageTooLarge, "message exceeds 2 MiB limit", http.StatusRequestEntityTooLarge)
	}
	if aerr := validateLineEndings(raw); aerr != nil {
		return nil, aerr
	}
	idx := bytes.Index(raw, []byte("\r\n\r\n"))
	if idx < 0 {
		return nil, errf(ReasonMalformedMessage, "missing empty line between header and body", http.StatusBadRequest)
	}
	head, body := raw[:idx], raw[idx+4:]

	msg := &Message{Body: body}
	if len(head) == 0 {
		return msg, nil
	}
	for _, line := range bytes.Split(head, []byte("\r\n")) {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if len(msg.Fields) == 0 {
				return nil, errf(ReasonMalformedMessage, "continuation line without a preceding field", http.StatusBadRequest)
			}
			last := &msg.Fields[len(msg.Fields)-1]
			last.Raw = append(last.Raw, '\r', '\n')
			last.Raw = append(last.Raw, line...)
			continue
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			return nil, errf(ReasonMalformedMessage, "header field without a colon separator", http.StatusBadRequest)
		}
		name := line[:colon]
		for _, c := range name {
			if c < 33 || c > 126 {
				return nil, errf(ReasonMalformedMessage, "invalid character in header field name", http.StatusBadRequest)
			}
		}
		msg.Fields = append(msg.Fields, HeaderField{
			Name: string(name),
			Raw:  append([]byte(nil), line...),
		})
	}
	return msg, nil
}
