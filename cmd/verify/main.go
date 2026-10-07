// Command verify runs the HTTP smoke suite against a live dkim-audit API:
// it waits for the API to become ready, replays the fixture messages, checks
// every verdict and reason code, and exits non-zero if anything deviates.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type smokeCase struct {
	Name             string `json:"name"`
	File             string `json:"file"`
	Status           int    `json:"status"`
	Archive          bool   `json:"archive"`
	BodyVerdict      string `json:"bodyVerdict"`
	BodyReason       string `json:"bodyReason"`
	SignatureVerdict string `json:"signatureVerdict"`
	SignatureReason  string `json:"signatureReason"`
}

type auditResponse struct {
	Domain   string `json:"domain"`
	Selector string `json:"selector"`
	BodyHash struct {
		Verdict string `json:"verdict"`
		Reason  string `json:"reason"`
	} `json:"bodyHash"`
	Signature struct {
		Verdict string `json:"verdict"`
		Reason  string `json:"reason"`
	} `json:"signature"`
	Archive bool `json:"archive"`
}

func main() {
	api := flag.String("api", envOr("API_URL", "http://127.0.0.1:8080"), "base URL of the dkim-audit API")
	fixtures := flag.String("fixtures", envOr("FIXTURES_DIR", "/fixtures"), "directory containing *.eml fixtures and cases.json")
	wait := flag.Duration("wait", 60*time.Second, "how long to wait for the API to become ready")
	flag.Parse()

	if err := waitReady(*api, *wait); err != nil {
		fmt.Printf("[smoke] FAIL: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("[smoke] API at %s is ready\n", *api)

	data, err := os.ReadFile(filepath.Join(*fixtures, "cases.json"))
	if err != nil {
		fmt.Printf("[smoke] FAIL: read cases.json: %v\n", err)
		os.Exit(2)
	}
	var cases []smokeCase
	if err := json.Unmarshal(data, &cases); err != nil {
		fmt.Printf("[smoke] FAIL: parse cases.json: %v\n", err)
		os.Exit(2)
	}

	passed := 0
	for _, tc := range cases {
		if err := runCase(*api, *fixtures, tc); err != nil {
			fmt.Printf("[smoke] FAIL %-32s %v\n", tc.Name, err)
			continue
		}
		fmt.Printf("[smoke] PASS %-32s (%s)\n", tc.Name, tc.File)
		passed++
	}

	fmt.Printf("[smoke] SUMMARY: %d/%d cases passed\n", passed, len(cases))
	if passed != len(cases) {
		os.Exit(1)
	}
}

func waitReady(api string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		resp, err := http.Get(api + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("API at %s not ready after %s", api, timeout)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func runCase(api, fixtures string, tc smokeCase) error {
	raw, err := os.ReadFile(filepath.Join(fixtures, tc.File))
	if err != nil {
		return fmt.Errorf("read fixture: %w", err)
	}
	resp, err := http.Post(api+"/api/dkim/audit", "application/rfc822", bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("POST: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != tc.Status {
		return fmt.Errorf("status: got %d, want %d (body: %s)", resp.StatusCode, tc.Status, body)
	}
	var got auditResponse
	if err := json.Unmarshal(body, &got); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	checks := []struct {
		label     string
		got, want string
	}{
		{"bodyHash.verdict", got.BodyHash.Verdict, tc.BodyVerdict},
		{"bodyHash.reason", got.BodyHash.Reason, tc.BodyReason},
		{"signature.verdict", got.Signature.Verdict, tc.SignatureVerdict},
		{"signature.reason", got.Signature.Reason, tc.SignatureReason},
	}
	for _, c := range checks {
		if c.got != c.want {
			return fmt.Errorf("%s: got %q, want %q", c.label, c.got, c.want)
		}
	}
	if got.Archive != tc.Archive {
		return fmt.Errorf("archive: got %v, want %v", got.Archive, tc.Archive)
	}
	return nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
