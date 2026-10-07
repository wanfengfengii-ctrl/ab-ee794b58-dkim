package dkim

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// Registry maps (signing domain, selector) pairs to RSA public keys. It is
// populated from a JSON file registered through the Compose configuration.
type Registry struct {
	keys map[string]*rsa.PublicKey
}

type keyFile struct {
	Keys []keyEntry `json:"keys"`
}

type keyEntry struct {
	Domain    string `json:"domain"`
	Selector  string `json:"selector"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"publicKey"`
}

func registryKey(domain, selector string) string {
	return strings.ToLower(domain) + "\x00" + strings.ToLower(selector)
}

// LoadRegistry reads the JSON key registry. Any malformed entry is a fatal
// configuration error: silently skipping a key would turn a typo into
// unexplained ERR_KEY_NOT_FOUND audit failures.
func LoadRegistry(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key registry: %w", err)
	}
	var doc keyFile
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse key registry %s: %w", path, err)
	}
	reg := &Registry{keys: make(map[string]*rsa.PublicKey, len(doc.Keys))}
	for i, e := range doc.Keys {
		if e.Domain == "" || e.Selector == "" {
			return nil, fmt.Errorf("key registry entry %d: domain and selector are required", i)
		}
		if e.Algorithm != "" && !strings.EqualFold(e.Algorithm, "rsa-sha256") {
			return nil, fmt.Errorf("key registry entry %d (%s/%s): unsupported algorithm %q", i, e.Domain, e.Selector, e.Algorithm)
		}
		pub, err := parsePublicKey(e.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("key registry entry %d (%s/%s): %w", i, e.Domain, e.Selector, err)
		}
		reg.keys[registryKey(e.Domain, e.Selector)] = pub
	}
	return reg, nil
}

// NewRegistry builds a registry from explicit keys; used by tests and the
// fixture generator.
func NewRegistry(entries map[[2]string]*rsa.PublicKey) *Registry {
	reg := &Registry{keys: make(map[string]*rsa.PublicKey, len(entries))}
	for k, v := range entries {
		reg.keys[registryKey(k[0], k[1])] = v
	}
	return reg
}

func parsePublicKey(s string) (*rsa.PublicKey, error) {
	s = strings.TrimSpace(s)
	var der []byte
	if block, _ := pem.Decode([]byte(s)); block != nil {
		der = block.Bytes
	} else {
		b, err := base64.StdEncoding.DecodeString(stripAllWSP(s))
		if err != nil {
			return nil, fmt.Errorf("public key is neither PEM nor base64 DER")
		}
		der = b
	}
	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
		return nil, fmt.Errorf("public key is not RSA")
	}
	if pub, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return pub, nil
	}
	return nil, fmt.Errorf("cannot parse RSA public key")
}

// Lookup returns the public key registered for (domain, selector).
func (r *Registry) Lookup(domain, selector string) (*rsa.PublicKey, bool) {
	pub, ok := r.keys[registryKey(domain, selector)]
	return pub, ok
}
