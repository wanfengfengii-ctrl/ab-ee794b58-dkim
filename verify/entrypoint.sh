#!/bin/sh
# One-shot verification job:
#   1. build sanity (byte-compile all application code)
#   2. wait until the API reports healthy
#   3. run the unit-test suite
#   4. run the HTTP smoke scenarios (valid mail, body rewrite, duplicates)
# The container exits non-zero if any stage fails, aggregating the stages.
set -u

API_URL="${DKIM_API_URL:-http://api:8080}"
APP_DIR="${DKIM_APP_DIR:-/srv/dkim/app}"
TEST_DIR="${DKIM_TEST_DIR:-/srv/dkim/tests}"
SMOKE_DIR="${DKIM_SMOKE_DIR:-/srv/dkim/smoke}"

rc=0

echo "== [1/4] build sanity: byte-compiling application =="
if python3 -m py_compile "$APP_DIR"/*.py; then
    echo "   compile OK"
else
    echo "   compile FAILED"
    rc=1
fi

echo "== [2/4] waiting for API at ${API_URL}/health =="
ready=0
i=0
while [ "$i" -lt 60 ]; do
    if python3 - "$API_URL" <<'PY'
import sys, urllib.request
try:
    with urllib.request.urlopen(sys.argv[1] + "/health", timeout=2) as r:
        sys.exit(0 if r.status == 200 else 1)
except Exception:
    sys.exit(1)
PY
    then
        ready=1
        echo "   API is healthy"
        break
    fi
    i=$((i + 1))
    sleep 1
done

if [ "$ready" -ne 1 ]; then
    echo "   API did not become ready in time"
    exit 1
fi

echo "== [3/4] unit tests =="
if DKIM_KEYRING="${DKIM_KEYRING:-/etc/dkim/keyring.json}" \
    PYTHONPATH="$APP_DIR" \
    python3 -m unittest discover -v -s "$TEST_DIR" -p 'test_*.py'; then
    echo "   unit tests OK"
else
    echo "   unit tests FAILED"
    rc=1
fi

echo "== [4/4] HTTP smoke tests =="
if DKIM_API_URL="$API_URL" python3 "$SMOKE_DIR/smoke_http.py"; then
    echo "   smoke tests OK"
else
    echo "   smoke tests FAILED"
    rc=1
fi

if [ "$rc" -eq 0 ]; then
    echo "ALL VERIFICATION STAGES PASSED"
else
    echo "VERIFICATION FAILED (see stages above)"
fi
exit "$rc"
