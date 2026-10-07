package httpapi

import (
	"encoding/json"
	"io"
	"log"
	"mime"
	"net/http"

	"dkim-audit/internal/dkim"
)

// NewHandler builds the API routes: POST /api/dkim/audit plus GET /healthz.
func NewHandler(reg *dkim.Registry) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/dkim/audit", auditHandler(reg))
	mux.HandleFunc("GET /healthz", healthHandler)
	return mux
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func auditHandler(reg *dkim.Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/rfc822" {
			writeError(w, http.StatusUnsupportedMediaType, dkim.ReasonUnsupportedMediaType,
				"Content-Type must be application/rfc822")
			return
		}

		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, dkim.MaxMessageSize))
		if err != nil {
			writeError(w, http.StatusRequestEntityTooLarge, dkim.ReasonMessageTooLarge,
				"message exceeds the 2 MiB limit")
			return
		}

		res, aerr := dkim.Audit(raw, reg)
		if aerr != nil {
			status := aerr.Status
			if status < 400 {
				status = http.StatusOK
			}
			if res == nil {
				res = dkim.FailureResult(aerr)
			}
			writeJSON(w, status, res)
			return
		}
		writeJSON(w, http.StatusOK, res)
	}
}

func writeError(w http.ResponseWriter, status int, reason, detail string) {
	writeJSON(w, status, dkim.FailureResult(&dkim.AuditError{Reason: reason, Detail: detail, Status: status}))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("encode response: %v", err)
	}
}
