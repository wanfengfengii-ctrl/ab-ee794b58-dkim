package dkim

// Stable reason codes returned by the audit API. These strings are part of
// the service contract: downstream archival tooling matches on them, so they
// must never be renamed or reused for a different meaning.
const (
	ReasonOK = "OK"

	// Request-shape violations (HTTP 4xx).
	ReasonMessageTooLarge        = "ERR_MESSAGE_TOO_LARGE"
	ReasonUnsupportedMediaType   = "ERR_UNSUPPORTED_MEDIA_TYPE"
	ReasonMethodNotAllowed       = "ERR_METHOD_NOT_ALLOWED"
	ReasonInvalidLineEndings     = "ERR_INVALID_LINE_ENDINGS"
	ReasonMalformedMessage       = "ERR_MALFORMED_MESSAGE"
	ReasonNoDKIMSignature        = "ERR_NO_DKIM_SIGNATURE"
	ReasonMultipleDKIMSignatures = "ERR_MULTIPLE_DKIM_SIGNATURES"

	// DKIM-Signature tag-list compliance violations (HTTP 200, audit fails).
	ReasonMalformedDKIMSignature = "ERR_MALFORMED_DKIM_SIGNATURE"
	ReasonDuplicateTag           = "ERR_DUPLICATE_TAG"
	ReasonMissingTag             = "ERR_MISSING_TAG"
	ReasonUnsupportedVersion     = "ERR_UNSUPPORTED_VERSION"
	ReasonUnsupportedAlgorithm   = "ERR_UNSUPPORTED_ALGORITHM"
	ReasonUnsupportedCanon       = "ERR_UNSUPPORTED_CANONICALIZATION"
	ReasonUnsupportedQueryMethod = "ERR_UNSUPPORTED_QUERY_METHOD"
	ReasonForbiddenBodyLengthTag = "ERR_FORBIDDEN_BODY_LENGTH_TAG"
	ReasonFromNotSigned          = "ERR_FROM_NOT_SIGNED"
	ReasonIdentityDomainMismatch = "ERR_IDENTITY_DOMAIN_MISMATCH"
	ReasonInvalidTagValue        = "ERR_INVALID_TAG_VALUE"

	// Strict archival policy: every instance of a signed header field must be
	// covered by the h= tag, otherwise a forwarding component could inject a
	// same-named header on top and have it picked by downstream consumers.
	ReasonHeaderInstancesNotFullySigned = "ERR_HEADER_INSTANCES_NOT_FULLY_SIGNED"

	// Key registry.
	ReasonKeyNotFound = "ERR_KEY_NOT_FOUND"
	ReasonKeyInvalid  = "ERR_KEY_INVALID"

	// Cryptographic verdicts.
	ReasonBodyHashMismatch  = "BODY_HASH_MISMATCH"
	ReasonSignatureMismatch = "SIGNATURE_MISMATCH"
)

// AuditError carries a stable reason code plus the HTTP status the API layer
// should use when the audit cannot produce per-part verdicts.
type AuditError struct {
	Reason string
	Detail string
	Status int
}

func (e *AuditError) Error() string {
	if e.Detail == "" {
		return e.Reason
	}
	return e.Reason + ": " + e.Detail
}

func errf(reason, detail string, status int) *AuditError {
	return &AuditError{Reason: reason, Detail: detail, Status: status}
}
