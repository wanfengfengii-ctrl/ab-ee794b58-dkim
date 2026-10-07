package dkim

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"net/http"
	"strings"
)

// Verdict is the independent audit outcome of one check.
type Verdict struct {
	Verdict string `json:"verdict"` // "pass" or "fail"
	Reason  string `json:"reason"`  // stable reason code
	Detail  string `json:"detail,omitempty"`
}

// Canonicalization names the header/body canonicalization modes in use.
type Canonicalization struct {
	Header string `json:"header"`
	Body   string `json:"body"`
}

// Result is the audit response. BodyHash and Signature are adjudicated
// independently; Archive is true only when both pass.
type Result struct {
	Domain           string           `json:"domain"`
	Selector         string           `json:"selector"`
	Canonicalization Canonicalization `json:"canonicalization"`
	BodyHash         Verdict          `json:"bodyHash"`
	Signature        Verdict          `json:"signature"`
	Archive          bool             `json:"archive"`
}

func pass() Verdict { return Verdict{Verdict: "pass", Reason: ReasonOK} }
func failV(a *AuditError) Verdict {
	return Verdict{Verdict: "fail", Reason: a.Reason, Detail: a.Detail}
}

// FailureResult converts a request-level or compliance-level error into the
// uniform response shape: both checks fail with the same reason code and the
// message must not be archived.
func FailureResult(aerr *AuditError) *Result {
	v := failV(aerr)
	return &Result{BodyHash: v, Signature: v, Archive: false}
}

// Audit verifies the single DKIM signature of a raw message against the key
// registry. A nil AuditError with a failing Result means the message was
// auditable and rejected; a non-nil AuditError means the audit could not
// complete — the Result is still returned (populated with whatever identity
// was parsed) so the caller can respond with the uniform shape.
func Audit(raw []byte, reg *Registry) (*Result, *AuditError) {
	msg, aerr := ParseMessage(raw)
	if aerr != nil {
		return nil, aerr
	}

	var sigFields []*HeaderField
	for i := range msg.Fields {
		if equalFoldASCII(msg.Fields[i].Name, "dkim-signature") {
			sigFields = append(sigFields, &msg.Fields[i])
		}
	}
	switch len(sigFields) {
	case 0:
		return nil, errf(ReasonNoDKIMSignature, "message has no DKIM-Signature header field", http.StatusBadRequest)
	case 1:
	default:
		return nil, errf(ReasonMultipleDKIMSignatures, "message has more than one DKIM-Signature header field", http.StatusBadRequest)
	}

	sig, aerr := ParseSignature(sigFields[0])
	if aerr != nil {
		return nil, aerr
	}

	res := &Result{
		Domain:           sig.Domain,
		Selector:         sig.Selector,
		Canonicalization: Canonicalization{Header: sig.HeaderCanon, Body: sig.BodyCanon},
	}
	reject := func(aerr *AuditError) (*Result, *AuditError) {
		v := failV(aerr)
		res.BodyHash, res.Signature = v, v
		return res, aerr
	}

	// Strict archival policy: if a signed header field name occurs more
	// often in the message than in the h= list, an upstream component could
	// have stacked an unsigned same-named field on top.
	if aerr := checkHeaderInstanceCoverage(msg, sig); aerr != nil {
		return reject(aerr)
	}

	pub, ok := reg.Lookup(sig.Domain, sig.Selector)
	if !ok {
		return reject(errf(ReasonKeyNotFound, "no public key registered for d="+sig.Domain+" s="+sig.Selector, http.StatusOK))
	}

	// Body hash adjudication (independent of the signature check).
	bodyDigest := sha256.Sum256(CanonicalizeBody(msg.Body, sig.BodyCanon))
	if bytes.Equal(bodyDigest[:], sig.BodyHash) {
		res.BodyHash = pass()
	} else {
		res.BodyHash = Verdict{Verdict: "fail", Reason: ReasonBodyHashMismatch, Detail: "canonicalized body hash differs from bh="}
	}

	// Signature adjudication over the signed headers.
	headerData := headerHashInput(msg, sig)
	headerDigest := sha256.Sum256(headerData)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, headerDigest[:], sig.Sig); err != nil {
		res.Signature = Verdict{Verdict: "fail", Reason: ReasonSignatureMismatch, Detail: "RSA signature does not verify"}
	} else {
		res.Signature = pass()
	}

	res.Archive = res.BodyHash.Verdict == "pass" && res.Signature.Verdict == "pass"
	return res, nil
}

// checkHeaderInstanceCoverage enforces that every header field name which is
// both signed and duplicated in the message is listed in h= at least as many
// times as it occurs, so the bottom-up selection cannot silently skip an
// injected instance.
func checkHeaderInstanceCoverage(msg *Message, sig *Signature) *AuditError {
	inMessage := make(map[string]int)
	for _, f := range msg.Fields {
		inMessage[strings.ToLower(f.Name)]++
	}
	inH := make(map[string]int)
	for _, name := range sig.HList {
		inH[name]++
	}
	for name, signed := range inH {
		if total := inMessage[name]; total > signed {
			return errf(ReasonHeaderInstancesNotFullySigned,
				"header field "+name+" occurs "+itoa(total)+" times but h= signs it only "+itoa(signed)+" time(s)",
				http.StatusOK)
		}
	}
	return nil
}

// headerHashInput builds the data the signature is verified over: the signed
// header fields selected bottom-up per h=, followed by the DKIM-Signature
// field with an emptied b= value.
func headerHashInput(msg *Message, sig *Signature) []byte {
	var buf []byte
	for _, f := range selectSignedFields(msg.Fields, sig.HList) {
		buf = append(buf, CanonicalizeHeader(f, sig.HeaderCanon)...)
	}
	return append(buf, CanonicalizeHeader(StripSignatureValue(sig.Field), sig.HeaderCanon)...)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
