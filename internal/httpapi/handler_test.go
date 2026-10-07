package httpapi

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"dkim-audit/internal/dkim"
)

func setup(t *testing.T) (http.Handler, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	reg := dkim.NewRegistry(map[[2]string]*rsa.PublicKey{
		{"example.com", "s1"}: &key.PublicKey,
	})
	return NewHandler(reg), key
}

func sign(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	msg := []byte("From: a@example.com\r\nSubject: hi\r\n\r\nbody\r\n")
	signed, err := dkim.Sign(msg, key, dkim.SignOptions{
		Domain: "example.com", Selector: "s1", Headers: []string{"from", "subject"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func doPost(t *testing.T, h http.Handler, contentType string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/dkim/audit", bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeResult(t *testing.T, rec *httptest.ResponseRecorder) *dkim.Result {
	t.Helper()
	var res dkim.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v (body %q)", err, rec.Body.String())
	}
	return &res
}

func TestHealthz(t *testing.T) {
	h, _ := setup(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz = %d", rec.Code)
	}
}

func TestAuditEndpointHappyPath(t *testing.T) {
	h, key := setup(t)
	rec := doPost(t, h, "application/rfc822", sign(t, key))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body %s", rec.Code, rec.Body.String())
	}
	res := decodeResult(t, rec)
	if !res.Archive || res.BodyHash.Verdict != "pass" || res.Signature.Verdict != "pass" {
		t.Fatalf("result = %+v", res)
	}
}

func TestAuditEndpointRejectsBadRequests(t *testing.T) {
	h, key := setup(t)
	signed := sign(t, key)

	t.Run("wrong content type", func(t *testing.T) {
		rec := doPost(t, h, "text/plain", signed)
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("status = %d", rec.Code)
		}
		if res := decodeResult(t, rec); res.BodyHash.Reason != dkim.ReasonUnsupportedMediaType || res.Archive {
			t.Fatalf("result = %+v", res)
		}
	})

	t.Run("oversize", func(t *testing.T) {
		rec := doPost(t, h, "application/rfc822", make([]byte, dkim.MaxMessageSize+1))
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d", rec.Code)
		}
		if res := decodeResult(t, rec); res.BodyHash.Reason != dkim.ReasonMessageTooLarge {
			t.Fatalf("result = %+v", res)
		}
	})

	t.Run("bare LF", func(t *testing.T) {
		raw := bytes.Replace(signed, []byte("\r\n"), []byte("\n"), 1)
		rec := doPost(t, h, "application/rfc822", raw)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d", rec.Code)
		}
		if res := decodeResult(t, rec); res.BodyHash.Reason != dkim.ReasonInvalidLineEndings {
			t.Fatalf("result = %+v", res)
		}
	})

	t.Run("method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/dkim/audit", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d", rec.Code)
		}
	})
}

func TestAuditEndpointExactlyTwoMiBAccepted(t *testing.T) {
	h, key := setup(t)
	signed := sign(t, key)
	// Pad the body with a huge comment line to reach exactly the limit.
	pad := dkim.MaxMessageSize - len(signed)
	if pad < 4 {
		t.Fatalf("fixture too large: %d", len(signed))
	}
	raw := append(signed, bytes.Repeat([]byte("x"), pad-2)...)
	raw = append(raw, '\r', '\n')
	if len(raw) != dkim.MaxMessageSize {
		t.Fatalf("len = %d", len(raw))
	}
	rec := doPost(t, h, "application/rfc822", raw)
	// The padding changed the body, so the audit fails — but the request
	// itself must be accepted (200) rather than rejected as oversize.
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	res := decodeResult(t, rec)
	if res.BodyHash.Reason != dkim.ReasonBodyHashMismatch {
		t.Fatalf("result = %+v", res)
	}
	if !strings.HasPrefix(res.Domain, "example.com") {
		t.Fatalf("domain = %q", res.Domain)
	}
}
