package main

import (
	"log"
	"net/http"
	"os"

	"dkim-audit/internal/dkim"
	"dkim-audit/internal/httpapi"
)

func main() {
	keysFile := getenv("DKIM_KEYS_FILE", "/etc/dkim-audit/keys.json")
	port := getenv("PORT", "8080")

	reg, err := dkim.LoadRegistry(keysFile)
	if err != nil {
		log.Fatalf("load key registry: %v", err)
	}
	log.Printf("loaded DKIM key registry from %s", keysFile)

	addr := ":" + port
	log.Printf("dkim-audit API listening on %s", addr)
	if err := http.ListenAndServe(addr, httpapi.NewHandler(reg)); err != nil {
		log.Fatal(err)
	}
}

func getenv(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
