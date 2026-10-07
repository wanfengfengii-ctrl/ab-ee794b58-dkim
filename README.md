# dkim-audit

DKIM re-verification service for the mail-forensics archival pipeline. Before
an external message is archived as trusted, this service re-audits its DKIM
signature so that forwarding components cannot fold headers, rewrite bodies,
or stack same-named headers and still have the message accepted.

## API

### `POST /api/dkim/audit`

- Request: `Content-Type: application/rfc822`, the raw message.
- Limits: at most **2 MiB**, every line boundary must be **CRLF**, and the
  message must contain **exactly one** `DKIM-Signature` header field.
- Policy: only `a=rsa-sha256`; only `simple`/`relaxed` header and body
  canonicalization; the `l=` body-length tag is forbidden; `h=` must cover
  `From`; folding, trailing empty body lines, and duplicate header fields
  (bottom-up selection) are handled per RFC 6376. Additionally, every
  instance of a signed, duplicated header field must be covered by `h=`
  (`ERR_HEADER_INSTANCES_NOT_FULLY_SIGNED`).

Response (always JSON, verdicts are independent):

```json
{
  "domain": "example.com",
  "selector": "s1",
  "canonicalization": {"header": "relaxed", "body": "simple"},
  "bodyHash":  {"verdict": "pass", "reason": "OK"},
  "signature": {"verdict": "pass", "reason": "OK"},
  "archive": true
}
```

`archive` is true only when **both** the body-hash check and the signature
check pass. Failure reasons are stable machine-readable codes:

| reason | meaning |
| --- | --- |
| `OK` | check passed |
| `BODY_HASH_MISMATCH` | canonicalized body hash differs from `bh=` |
| `SIGNATURE_MISMATCH` | RSA signature does not verify |
| `ERR_KEY_NOT_FOUND` | no key registered for `d=`/`s=` |
| `ERR_MESSAGE_TOO_LARGE` | body exceeds 2 MiB (HTTP 413) |
| `ERR_UNSUPPORTED_MEDIA_TYPE` | Content-Type is not `application/rfc822` (HTTP 415) |
| `ERR_INVALID_LINE_ENDINGS` | bare LF/CR found (HTTP 400) |
| `ERR_MALFORMED_MESSAGE` | no header/body separator etc. (HTTP 400) |
| `ERR_NO_DKIM_SIGNATURE` / `ERR_MULTIPLE_DKIM_SIGNATURES` | signature field count != 1 (HTTP 400) |
| `ERR_MALFORMED_DKIM_SIGNATURE` / `ERR_DUPLICATE_TAG` / `ERR_MISSING_TAG` / `ERR_INVALID_TAG_VALUE` | tag-list syntax/compliance |
| `ERR_UNSUPPORTED_VERSION` / `ERR_UNSUPPORTED_ALGORITHM` / `ERR_UNSUPPORTED_CANONICALIZATION` / `ERR_UNSUPPORTED_QUERY_METHOD` | unsupported tag values |
| `ERR_FORBIDDEN_BODY_LENGTH_TAG` | `l=` present |
| `ERR_FROM_NOT_SIGNED` | `h=` does not cover `From` |
| `ERR_IDENTITY_DOMAIN_MISMATCH` | `i=` outside the `d=` domain |
| `ERR_HEADER_INSTANCES_NOT_FULLY_SIGNED` | duplicated signed header not fully covered by `h=` |

### `GET /healthz`

Returns `200 {"status":"ok"}`; used by the Compose health check.

## Key registry

`keys/keys.json` (mounted into the api container) registers RSA public keys
by signing domain and selector:

```json
{
  "keys": [
    {"domain": "example.com", "selector": "s1", "algorithm": "rsa-sha256",
     "publicKey": "-----BEGIN PUBLIC KEY-----\n..."}
  ]
}
```

`publicKey` accepts PEM (`PUBLIC KEY` / `RSA PUBLIC KEY`) or base64 DER.
The path is configured with `DKIM_KEYS_FILE` (default
`/etc/dkim-audit/keys.json`); the listen port with `PORT` (default `8080`).

## Run with Compose

```sh
API_PORT=8080 docker compose up --build api      # serve on host port 8080
```

The host-side port is configurable through `API_PORT` (default `8080`).

## One-shot verification

The `verify` service waits for the API to become healthy, runs the code
tests (`go test ./...`) and the build (`go build ./...`), then executes the
HTTP smoke suite (valid message, rewritten body, stacked duplicate header,
unknown key, forbidden `l=` tag) and exits with a summarizing code:

```sh
docker compose up --build --abort-on-container-exit --exit-code-from verify verify
echo $?   # 0 = everything passed
```

## Development

```sh
go test ./...                 # unit + handler tests
go run ./scripts/genfixtures  # regenerate fixtures + keys/keys.json (rotates the test key)
go build -o server ./cmd/server && DKIM_KEYS_FILE=keys/keys.json ./server
go build -o verify ./cmd/verify && ./verify -api http://127.0.0.1:8080 -fixtures fixtures
```

`fixtures/` and `keys/keys.json` are generated together; the committed
fixture key is a throwaway test key, never used for real mail.
