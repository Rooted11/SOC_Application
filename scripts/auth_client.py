#!/usr/bin/env python3
"""
Small auth helper for operator scripts.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import time
from functools import lru_cache
import urllib.error
import urllib.request


def _request_json(url: str, *, method: str = "GET", payload: dict | None = None, headers=None):
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        url,
        data=body,
        headers=headers or {},
        method=method,
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        data = response.read()
    return json.loads(data) if data else {}


def _normalize_totp_secret(secret: str) -> str:
    return "".join(secret.strip().upper().split())


def _decode_totp_secret(secret: str) -> bytes:
    normalized = _normalize_totp_secret(secret)
    padding = "=" * (-len(normalized) % 8)
    return base64.b32decode(normalized + padding, casefold=True)


def _generate_totp_code(secret: str, *, for_time: int | None = None) -> str:
    timestamp = int(time.time() if for_time is None else for_time)
    counter = timestamp // 30
    counter_bytes = struct.pack(">Q", counter)
    digest = hmac.new(_decode_totp_secret(secret), counter_bytes, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % 1_000_000).zfill(6)


def _resolve_otp_code() -> str | None:
    explicit_code = os.getenv("AUTH_OTP_CODE")
    if explicit_code:
        return explicit_code

    totp_secret = os.getenv("AUTH_TOTP_SECRET")
    if totp_secret:
        return _generate_totp_code(totp_secret)

    return None


@lru_cache(maxsize=8)
def get_access_token(base_url: str) -> str | None:
    base_url = base_url.rstrip("/")
    status = _request_json(f"{base_url}/api/auth/status")
    if not status.get("auth_enabled"):
        return None

    username = os.getenv("AUTH_USERNAME")
    password = os.getenv("AUTH_PASSWORD")
    if not username or not password:
        raise RuntimeError(
            "Backend authentication is enabled. Set AUTH_USERNAME and AUTH_PASSWORD "
            "before running this script."
        )

    payload = {"username": username, "password": password}
    if status.get("mfa_enabled"):
        otp_code = _resolve_otp_code()
        if not otp_code:
            raise RuntimeError(
                "Backend MFA is enabled. Set AUTH_OTP_CODE or AUTH_TOTP_SECRET before "
                "running this script."
            )
        payload["otp_code"] = otp_code

    try:
        login = _request_json(
            f"{base_url}/api/auth/login",
            method="POST",
            payload=payload,
            headers={"Content-Type": "application/json"},
        )
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Could not authenticate to backend: {exc.code} {detail}") from exc

    return login.get("access_token")


def json_headers(base_url: str) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    token = get_access_token(base_url)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers
