"""HTTP server for the isolated maintenance station.

Stdlib-only threaded HTTP server exposing:

- ``GET  /healthz``        health response
- ``GET  /``               operator UI
- ``GET  /api/demo``       built-in exercise packages
- ``GET  /api/verdicts``   persisted verdicts/receipts (review after restart)
- ``POST /api/inspect``    dry-run evaluation, per-level report, first reason
- ``POST /api/execute``    idempotent adjudicated execution
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import demo
from .chain import evaluate, format_time
from .crypto import JsonError, sha256_hex, strict_loads
from .store import Store

MAX_BODY = 1 << 20

ERROR_CODES = {
    "signature": "signature-invalid",
    "narrowing": "scope-widened",
    "root": "root-untrusted",
    "time": "expired",
    "revocation": "revoked",
    "request": "out-of-scope",
}


def _error_code(first_error: str) -> str:
    if not first_error:
        return "invalid"
    lowered = first_error.lower()
    for needle, code in ERROR_CODES.items():
        if needle in lowered:
            return code
    if "撤销" in first_error:
        return "revoked"
    if "过期" in first_error or "有效窗口" in first_error:
        return "expired"
    if "签名" in first_error:
        return "signature-invalid"
    if "越" in first_error or "超出" in first_error:
        return "out-of-scope"
    return "invalid"


def build_receipt(report, request, now: datetime) -> dict:
    verdict_key = report.verdict_key
    return {
        "receipt_id": "rcpt-" + verdict_key[:32],
        "execution_id": "exec-" + sha256_hex(f"exec:{verdict_key}".encode())[:32],
        "verdict_key": verdict_key,
        "root_key": report.root_key,
        "chain_digest": report.chain_digest,
        "leaf_id": report.leaf_id,
        "device": request["device"],
        "command": request["command"],
        "request_hash": report.request_hash,
        "status": "executed",
        "executed_at": format_time(now),
        "result": {
            "outcome": "completed",
            "detail": f"设备 {request['device']} 已执行 {request['command']}",
            "params": request.get("params", {}),
        },
    }


class Station:
    """Holds configuration and the persistent store."""

    def __init__(self):
        self.data_dir = os.environ.get("DATA_DIR", "/data")
        self.store = Store(self.data_dir)
        roots = set()
        extra = os.environ.get("TRUSTED_ROOTS", "")
        for token in extra.split(","):
            token = token.strip().lower()
            if token:
                roots.add(token)
        self.demo_enabled = os.environ.get("DEMO_ROOT_ENABLED", "1") != "0"
        if self.demo_enabled:
            roots.add(demo.DEMO_ROOT_KEY)
        self.trusted_roots = roots

    def inspect(self, package, request):
        return evaluate(
            package,
            request,
            self.trusted_roots,
            leaf_used_lookup=self.store.leaf_used,
        )

    def execute(self, package, request):
        """Adjudicate and (if valid) execute exactly once per verdict key."""
        report = self.inspect(package, request)
        if not report.ok:
            return 400, {
                "ok": False,
                "code": _error_code(report.first_error),
                "error": report.first_error,
                "report": report.to_dict(),
            }

        now = datetime.now(timezone.utc)
        with self.store.lock:
            existing = self.store.get_by_verdict_key(report.verdict_key)
            if existing is not None:
                return 200, {
                    "ok": True,
                    "replay": True,
                    "receipt": existing,
                    "report": report.to_dict(),
                }
            used = self.store.get_by_leaf_key(report.leaf_key)
            if used is not None:
                return 409, {
                    "ok": False,
                    "code": "leaf-already-used",
                    "error": "末级凭据已使用，不能再次驱动设备",
                    "original_verdict_key": used["verdict_key"],
                    "report": report.to_dict(),
                }
            receipt = build_receipt(report, request, now)
            record = {
                "verdict_key": report.verdict_key,
                "leaf_key": report.leaf_key,
                "root_key": report.root_key,
                "chain_digest": report.chain_digest,
                "leaf_id": report.leaf_id,
                "request": request,
                "request_hash": report.request_hash,
                "receipt": receipt,
                "created_at": format_time(now),
            }
            try:
                self.store.insert_verdict(record)
            except sqlite3.IntegrityError:
                # A concurrent writer won the race; converge on its receipt.
                winner = self.store.get_by_verdict_key(report.verdict_key)
                if winner is not None:
                    return 200, {
                        "ok": True,
                        "replay": True,
                        "receipt": winner,
                        "report": report.to_dict(),
                    }
                used = self.store.get_by_leaf_key(report.leaf_key)
                return 409, {
                    "ok": False,
                    "code": "leaf-already-used",
                    "error": "末级凭据已使用，不能再次驱动设备",
                    "original_verdict_key": used["verdict_key"] if used else None,
                    "report": report.to_dict(),
                }
            return 200, {
                "ok": True,
                "replay": False,
                "receipt": receipt,
                "report": report.to_dict(),
            }


def _json_bytes(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")


def make_handler(station: Station, index_html: bytes):
    class Handler(BaseHTTPRequestHandler):
        server_version = "StationHTTP/1.0"
        protocol_version = "HTTP/1.1"

        # -- helpers --------------------------------------------------------
        def _send(self, status, body: bytes, content_type="application/json; charset=utf-8"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_json(self, status, obj):
            self._send(status, _json_bytes(obj))

        def _read_json_body(self):
            length = self.headers.get("Content-Length")
            if length is None:
                self._send_json(411, {"ok": False, "error": "missing Content-Length"})
                return None
            try:
                length = int(length)
            except ValueError:
                self._send_json(400, {"ok": False, "error": "bad Content-Length"})
                return None
            if length > MAX_BODY:
                self._send_json(413, {"ok": False, "error": "body too large"})
                return None
            raw = self.rfile.read(length)
            try:
                return strict_loads(raw)
            except JsonError as exc:
                self._send_json(400, {"ok": False, "code": "malformed", "error": str(exc)})
                return None

        def log_message(self, fmt, *args):  # keep container logs tidy
            pass

        # -- routes -----------------------------------------------------------
        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path == "/healthz":
                self._send_json(
                    200,
                    {
                        "status": "ok",
                        "time": format_time(datetime.now(timezone.utc)),
                        "verdicts_persisted": station.store.count(),
                    },
                )
            elif path == "/" or path == "/index.html":
                self._send(200, index_html, "text/html; charset=utf-8")
            elif path == "/api/demo":
                if not station.demo_enabled:
                    self._send_json(404, {"ok": False, "error": "demo disabled"})
                else:
                    self._send_json(200, {"ok": True, "scenarios": demo.build_scenarios()})
            elif path == "/api/verdicts":
                self._send_json(
                    200, {"ok": True, "verdicts": station.store.list_verdicts()}
                )
            else:
                self._send_json(404, {"ok": False, "error": "not found"})

        def do_POST(self):
            path = self.path.split("?", 1)[0]
            if path not in ("/api/inspect", "/api/execute"):
                self._send_json(404, {"ok": False, "error": "not found"})
                return
            body = self._read_json_body()
            if body is None:
                return
            if not isinstance(body, dict) or "package" not in body or "request" not in body:
                self._send_json(
                    400,
                    {
                        "ok": False,
                        "code": "malformed",
                        "error": "body must be an object with 'package' and 'request'",
                    },
                )
                return
            package = body["package"]
            request = body["request"]
            if path == "/api/inspect":
                report = station.inspect(package, request)
                self._send_json(200, report.to_dict())
            else:
                status, payload = station.execute(package, request)
                self._send_json(status, payload)

    return Handler


def main():
    port = int(os.environ.get("PORT", "8000"))
    station = Station()
    static_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    with open(static_path, "rb") as handle:
        index_html = handle.read()
    server = ThreadingHTTPServer(("0.0.0.0", port), make_handler(station, index_html))
    server.daemon_threads = True
    print(f"station listening on 0.0.0.0:{port}, data dir {station.data_dir}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        station.store.close()


if __name__ == "__main__":
    main()
