#!/bin/sh
# One-shot verification entrypoint. The Compose api service is already
# healthy when this starts (depends_on: service_healthy); the smoke binary
# additionally polls /healthz itself so the script is safe to run standalone.
#
# Steps: code tests -> build -> HTTP smoke. Any failure aborts with a
# non-zero exit code; the smoke suite's exit code summarizes the cases.
set -eu

cd /src

echo "== [verify] 1/3: go test ./... =="
go test ./...

echo "== [verify] 2/3: go build ./... =="
go build ./...

echo "== [verify] 3/3: HTTP smoke suite against ${API_URL} =="
exec /usr/local/bin/verify -api "${API_URL}" -fixtures "${FIXTURES_DIR}" -wait 60s
