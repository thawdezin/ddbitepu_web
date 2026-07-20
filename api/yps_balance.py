"""Protected Vercel proxy for YPS card-balance lookups.

The mobile app presents a short-lived HMAC proof containing a timestamp, nonce,
and card number. The upstream SM2 private key is read only from Vercel's
environment and is never returned, logged, or bundled into the Android app.
"""

from __future__ import annotations

import json
import os
import time
import uuid
import hashlib
import hmac
import re
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler
from typing import Any
from zoneinfo import ZoneInfo

import requests
from gmssl import func, sm2


UPSTREAM_URL = (
    "http://103.113.87.142:10010/account/query/getCardBalance/V1"
)
MAX_BODY_BYTES = 2_048
UPSTREAM_TIMEOUT_SECONDS = 15
YANGON_TIME_ZONE = ZoneInfo("Asia/Yangon")
REQUEST_MAX_AGE_SECONDS = 60
NONCE_PATTERN = re.compile(r"^[0-9a-f]{32}$")

STID = os.environ.get("YPS_STID", "20000002")
MCHID = os.environ.get("YPS_MCHID", "000400900000003")
LANGID = os.environ.get("YPS_LANGID", "EN")
PRIVATE_KEY = os.environ.get("YPS_PRIVATE_KEY", "").strip().upper()
REQUEST_SIGNING_KEY = os.environ.get("DDP_REQUEST_SIGNING_KEY", "").strip()
_seen_nonces: dict[str, float] = {}
_nonce_lock = threading.Lock()


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )


def _verify_request_signature(
    card_number: str,
    timestamp_text: str,
    nonce: str,
    supplied_signature: str,
    now: float | None = None,
) -> None:
    if not REQUEST_SIGNING_KEY:
        raise RuntimeError("DDP_REQUEST_SIGNING_KEY is not configured")
    if not timestamp_text.isdigit() or not NONCE_PATTERN.fullmatch(nonce):
        raise ValueError("invalid request proof")

    instant = time.time() if now is None else now
    request_time = int(timestamp_text) / 1_000
    if abs(instant - request_time) > REQUEST_MAX_AGE_SECONDS:
        raise ValueError("expired request proof")

    message = f"{timestamp_text}\n{nonce}\n{card_number}".encode("utf-8")
    expected = hmac.new(
        REQUEST_SIGNING_KEY.encode("utf-8"),
        message,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, supplied_signature.lower()):
        raise ValueError("invalid request signature")

    # This blocks immediate replay within a warm function instance. Vercel WAF
    # remains the cross-instance protection because serverless memory is not a
    # durable global nonce store.
    with _nonce_lock:
        cutoff = instant - REQUEST_MAX_AGE_SECONDS
        expired = [key for key, seen_at in _seen_nonces.items() if seen_at < cutoff]
        for key in expired:
            del _seen_nonces[key]
        if nonce in _seen_nonces:
            raise ValueError("replayed request proof")
        _seen_nonces[nonce] = instant


def _build_upstream_body(card_number: str, now: float | None = None) -> dict[str, Any]:
    if not PRIVATE_KEY:
        raise RuntimeError("YPS_PRIVATE_KEY is not configured")

    instant = time.time() if now is None else now
    local = datetime.fromtimestamp(instant, tz=YANGON_TIME_ZONE)
    request_date = local.strftime("%Y%m%d")
    request_time = local.strftime("%H%M%S")
    serial = str(int(instant * 1_000))

    sign_fields = {
        "joininstid": STID,
        "joininstssn": serial,
        "reqdate": request_date,
        "reqtime": request_time,
    }
    sign_text = "".join(
        key + sign_fields[key] for key in sorted(sign_fields.keys())
    )

    public_key = sm2.CryptSM2(
        private_key=PRIVATE_KEY,
        public_key="00" * 64,
    )._kg(int(PRIVATE_KEY, 16), sm2.default_ecc_table["g"])
    signer = sm2.CryptSM2(private_key=PRIVATE_KEY, public_key=public_key)
    signature = signer.sign_with_sm3(
        sign_text.encode("utf-8"),
        func.random_hex(64),
    )

    return {
        **sign_fields,
        "mchntid": MCHID,
        "reqlangid": LANGID,
        "sign": signature,
        "data": {"cardno": card_number},
    }


def _query_yps(card_number: str) -> dict[str, Any]:
    response = requests.post(
        UPSTREAM_URL,
        json=_build_upstream_body(card_number),
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "Charset": "utf-8",
        },
        timeout=UPSTREAM_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    decoded = response.json()
    if not isinstance(decoded, dict):
        raise ValueError("YPS response root is not an object")
    return decoded


class handler(BaseHTTPRequestHandler):
    server_version = ""
    sys_version = ""

    def _send_json(
        self,
        status: int,
        payload: dict[str, Any],
        request_id: str,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        body = _json_bytes(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Request-Id", request_id)
        if extra_headers:
            for name, value in extra_headers.items():
                self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        request_id = uuid.uuid4().hex
        self._send_json(
            405,
            {"error": "method_not_allowed", "request_id": request_id},
            request_id,
            {"Allow": "POST"},
        )

    def do_HEAD(self) -> None:  # noqa: N802
        self.send_response(405)
        self.send_header("Allow", "POST")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        request_id = uuid.uuid4().hex
        started = time.monotonic()

        content_type = self.headers.get("Content-Type", "").lower()
        if not content_type.startswith("application/json"):
            self._send_json(
                415,
                {"error": "unsupported_media_type", "request_id": request_id},
                request_id,
            )
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length <= 0 or length > MAX_BODY_BYTES:
            self._send_json(
                413,
                {"error": "invalid_body_size", "request_id": request_id},
                request_id,
            )
            return

        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(
                400,
                {"error": "invalid_json", "request_id": request_id},
                request_id,
            )
            return

        card_number = payload.get("card_number") if isinstance(payload, dict) else None
        if (
            not isinstance(card_number, str)
            or len(card_number) != 19
            or not card_number.isascii()
            or not card_number.isdigit()
        ):
            self._send_json(
                422,
                {"error": "invalid_card_number", "request_id": request_id},
                request_id,
            )
            return

        try:
            _verify_request_signature(
                card_number,
                self.headers.get("X-DDP-Timestamp", ""),
                self.headers.get("X-DDP-Nonce", "").lower(),
                self.headers.get("X-DDP-Signature", ""),
            )
        except Exception as error:  # Never disclose verification details.
            print(
                json.dumps(
                    {
                        "event": "yps_auth_rejected",
                        "request_id": request_id,
                        "reason": type(error).__name__,
                    }
                )
            )
            self._send_json(
                401,
                {"error": "unauthorized", "request_id": request_id},
                request_id,
            )
            return

        try:
            result = _query_yps(card_number)
            status = 200
        except requests.Timeout:
            result = {"error": "upstream_timeout", "request_id": request_id}
            status = 504
        except (requests.RequestException, ValueError, RuntimeError) as error:
            print(
                json.dumps(
                    {
                        "event": "yps_upstream_failed",
                        "request_id": request_id,
                        "reason": type(error).__name__,
                    }
                )
            )
            result = {"error": "upstream_unavailable", "request_id": request_id}
            status = 502

        print(
            json.dumps(
                {
                    "event": "yps_request_complete",
                    "request_id": request_id,
                    "status": status,
                    "elapsed_ms": round((time.monotonic() - started) * 1_000),
                }
            )
        )
        self._send_json(status, result, request_id)

    def log_message(self, format: str, *args: Any) -> None:
        # Disable BaseHTTPRequestHandler's raw request logging; it can include
        # information that should not be retained by the balance service.
        return
