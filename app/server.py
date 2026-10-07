"""HTTP frontend for the DKIM audit service.

POST /api/dkim/audit  -- raw RFC 822 message with Content-Type
                         application/rfc822 (max 2 MiB, CRLF framed)
GET  /health          -- liveness/readiness probe
GET  /                -- minimal service description

The verdict JSON always carries the stable ``reason_code``; HTTP status codes
are only a coarse grouping so archivers should gate on ``decision``.
"""

from __future__ import annotations

import json
import os
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dkim_core  # noqa: E402

LISTEN_HOST = os.environ.get("DKIM_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("DKIM_LISTEN_PORT", "8080"))
KEYRING_PATH = os.environ.get(
    "DKIM_KEYRING", "/etc/dkim/keyring.json"
)

REASON_STATUS = {
    dkim_core.OK: HTTPStatus.OK,
    dkim_core.NO_SIGNATURE: HTTPStatus.BAD_REQUEST,
    dkim_core.MULTIPLE_SIGNATURES: HTTPStatus.BAD_REQUEST,
    dkim_core.MALFORMED_MESSAGE: HTTPStatus.BAD_REQUEST,
    dkim_core.MALFORMED_SIGNATURE: HTTPStatus.BAD_REQUEST,
    dkim_core.NONCOMPLIANT_TAG: HTTPStatus.BAD_REQUEST,
    dkim_core.L_TAG_FORBIDDEN: HTTPStatus.BAD_REQUEST,
    dkim_core.FROM_NOT_SIGNED: HTTPStatus.BAD_REQUEST,
    dkim_core.UNSUPPORTED_ALGORITHM: HTTPStatus.BAD_REQUEST,
    dkim_core.UNSUPPORTED_CANONICALIZATION: HTTPStatus.BAD_REQUEST,
    dkim_core.MESSAGE_TOO_LARGE: HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
    dkim_core.UNKNOWN_KEY: HTTPStatus.NOT_FOUND,
    dkim_core.KEY_UNAVAILABLE: HTTPStatus.SERVICE_UNAVAILABLE,
    dkim_core.BODY_HASH_MISMATCH: HTTPStatus.UNPROCESSABLE_ENTITY,
    dkim_core.SIGNATURE_MISMATCH: HTTPStatus.UNPROCESSABLE_ENTITY,
    dkim_core.INTERNAL_ERROR: HTTPStatus.INTERNAL_SERVER_ERROR,
}


class KeyringHolder:
    """Loads the compose-provided keyring once (read-only mount)."""

    def __init__(self, path: str):
        self.path = path
        self.keyring = dkim_core.load_keyring(path)


class AuditHandler(BaseHTTPRequestHandler):
    server_version = "DkimAudit/1.0"

    # Quieter, single-line access logging suitable for containers.
    def log_message(self, fmt: str, *args: object) -> None:
        sys.stdout.write(
            "%s - - %s\n" % (self.address_string(), fmt % args)
        )

    def _send_json(self, status: HTTPStatus, payload: dict) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._send_json(
                HTTPStatus.OK,
                {"status": "healthy", "service": "dkim-audit"},
            )
        elif self.path == "/":
            self._send_json(
                HTTPStatus.OK,
                {
                    "service": "dkim-audit",
                    "endpoint": "/api/dkim/audit",
                    "content_type": "application/rfc822",
                    "max_bytes": dkim_core.MAX_MESSAGE_SIZE,
                },
            )
        else:
            self._send_json(
                HTTPStatus.NOT_FOUND,
                {"decision": "reject", "reason_code": "NOT_FOUND"},
            )

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/api/dkim/audit":
            self._send_json(
                HTTPStatus.NOT_FOUND,
                {"decision": "reject", "reason_code": "NOT_FOUND"},
            )
            return

        ctype = self.headers.get("Content-Type", "")
        main_type = ctype.split(";", 1)[0].strip().lower()
        if main_type != "application/rfc822":
            self._send_json(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                {
                    "decision": "reject",
                    "reason_code": "UNSUPPORTED_CONTENT_TYPE",
                    "expected": "application/rfc822",
                },
            )
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0:
            self._send_json(
                HTTPStatus.LENGTH_REQUIRED,
                {"decision": "reject", "reason_code": "LENGTH_REQUIRED"},
            )
            return
        if length > dkim_core.MAX_MESSAGE_SIZE:
            # Drain a bounded amount so a well-behaved client that is still
            # streaming the (slightly) oversized body does not receive RST
            # before reading the 413. Wildly large uploads are abandoned.
            drain = min(length, dkim_core.MAX_MESSAGE_SIZE + 65536)
            remaining = drain
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    break
                remaining -= len(chunk)
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"decision": "reject", "reason_code": dkim_core.MESSAGE_TOO_LARGE},
            )
            if drain != length:
                self.close_connection = True
            return

        data = self.rfile.read(length)
        result = dkim_core.audit(data, self.server.keyring)  # type: ignore[attr-defined]
        payload = result.to_dict()
        status = REASON_STATUS.get(
            result.reason_code, HTTPStatus.INTERNAL_SERVER_ERROR
        )
        self._send_json(status, payload)


class AuditHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, keyring):
        super().__init__(address, handler)
        self.keyring = keyring


def main() -> int:
    holder = KeyringHolder(KEYRING_PATH)
    server = AuditHTTPServer(
        (LISTEN_HOST, LISTEN_PORT), AuditHandler, holder.keyring
    )
    sys.stdout.write(
        "dkim-audit listening on %s:%d keyring=%s\n"
        % (LISTEN_HOST, LISTEN_PORT, KEYRING_PATH)
    )
    sys.stdout.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
