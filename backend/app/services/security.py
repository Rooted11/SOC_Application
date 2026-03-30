"""
Authentication helpers, bearer-token validation, and TOTP MFA primitives.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Set

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.logging_config import get_logger
from .config import settings

logger = get_logger(__name__)
from . import rbac


bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class AuthenticatedUser:
    username: str
    mfa_authenticated: bool = False
    roles: List[str] = field(default_factory=list)
    permissions: Set[str] = field(default_factory=set)
    is_super_admin: bool = False


class InvalidTokenError(Exception):
    """Raised when a bearer token fails validation."""


def _b64_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _sign(value: str) -> str:
    digest = hmac.new(
        settings.auth_token_secret.encode("utf-8"),
        value.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return _b64_encode(digest)


def _normalize_totp_secret(secret: str) -> str:
    return "".join(secret.strip().upper().split())


def _decode_totp_secret(secret: str) -> bytes:
    normalized = _normalize_totp_secret(secret)
    padding = "=" * (-len(normalized) % 8)
    return base64.b32decode(normalized + padding, casefold=True)


def authenticate_credentials(username: str, password: str) -> bool:
    resolved = rbac.verify_user_credentials(username, password)
    if resolved:
        return True
    return hmac.compare_digest(username, settings.auth_username) and hmac.compare_digest(
        password, settings.auth_password
    )


def create_access_token(username: str, *, mfa_authenticated: bool = False) -> str:
    issued_at = int(time.time())
    payload = {
        "sub": username,
        "iat": issued_at,
        "exp": issued_at + settings.auth_token_ttl_minutes * 60,
        "mfa": bool(mfa_authenticated),
    }
    encoded_payload = _b64_encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    signature = _sign(encoded_payload)
    return f"{encoded_payload}.{signature}"


def verify_access_token(token: str) -> AuthenticatedUser:
    try:
        encoded_payload, encoded_signature = token.split(".", 1)
    except ValueError as exc:
        raise InvalidTokenError("Malformed access token") from exc

    expected_signature = _sign(encoded_payload)
    if not hmac.compare_digest(encoded_signature, expected_signature):
        raise InvalidTokenError("Invalid access token signature")

    try:
        payload = json.loads(_b64_decode(encoded_payload).decode("utf-8"))
    except (ValueError, json.JSONDecodeError) as exc:
        raise InvalidTokenError("Invalid access token payload") from exc

    username = payload.get("sub")
    expires_at = int(payload.get("exp", 0))
    if not username:
        raise InvalidTokenError("Missing access token subject")
    if expires_at <= int(time.time()):
        raise InvalidTokenError("Access token expired")

    return AuthenticatedUser(
        username=username,
        mfa_authenticated=bool(payload.get("mfa")),
    )


def generate_totp_code(
    secret: str,
    *,
    for_time: int | None = None,
    period_seconds: int = 30,
    digits: int = 6,
) -> str:
    timestamp = int(time.time() if for_time is None else for_time)
    counter = timestamp // period_seconds
    counter_bytes = struct.pack(">Q", counter)
    digest = hmac.new(_decode_totp_secret(secret), counter_bytes, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10**digits)).zfill(digits)


def verify_totp_code(
    secret: str,
    code: str,
    *,
    now: int | None = None,
    valid_window: int = 1,
) -> bool:
    if not code or not code.isdigit():
        return False

    current_time = int(time.time() if now is None else now)
    for offset in range(-valid_window, valid_window + 1):
        if hmac.compare_digest(
            generate_totp_code(secret, for_time=current_time + (offset * 30)),
            code,
        ):
            return True
    return False


def build_totp_uri(secret: str, *, username: str, issuer: str) -> str:
    normalized_secret = _normalize_totp_secret(secret)
    label = urllib.parse.quote(f"{issuer}:{username}")
    issuer_param = urllib.parse.quote(issuer)
    return (
        f"otpauth://totp/{label}?secret={normalized_secret}&issuer={issuer_param}"
        "&algorithm=SHA1&digits=6&period=30"
    )


def get_request_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for:
        first_hop = forwarded_for.split(",")[0].strip()
        if first_hop:
            return first_hop
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def is_mfa_enabled() -> bool:
    return settings.auth_mfa_enabled and bool(settings.auth_totp_secret)


def _auth_exception(detail: str = "Authentication required") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> AuthenticatedUser:
    if not settings.auth_enabled:
        return AuthenticatedUser(
            username="local-dev",
            mfa_authenticated=False,
            roles=["super_admin"],
            permissions={"*"},
            is_super_admin=True,
        )

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _auth_exception()

    try:
        raw_user = verify_access_token(credentials.credentials)
    except InvalidTokenError as exc:
        raise _auth_exception(str(exc)) from exc

    resolved = rbac.resolve_user(raw_user.username)
    if resolved:
        return AuthenticatedUser(
            username=resolved.username,
            mfa_authenticated=raw_user.mfa_authenticated,
            roles=resolved.roles,
            permissions=resolved.permissions,
            is_super_admin=resolved.is_super_admin,
        )

    # Fallback to legacy single-user auth
    is_env_user = hmac.compare_digest(raw_user.username, settings.auth_username)
    return AuthenticatedUser(
        username=raw_user.username,
        mfa_authenticated=raw_user.mfa_authenticated,
        roles=["super_admin"] if is_env_user else [],
        permissions={"*"} if is_env_user else set(),
        is_super_admin=is_env_user,
    )


def get_agent_or_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> AuthenticatedUser | None:
    """
    Allow either a normal authenticated user or a local ingest agent token.
    The agent token is intended for lab/internal forwarders only.
    """
    agent_header = request.headers.get("x-agent-token")
    bearer_token = credentials.credentials if credentials else None
    client_ip    = get_request_client_ip(request)
    if settings.ingest_token and agent_header:
        if hmac.compare_digest(agent_header, settings.ingest_token):
            return AuthenticatedUser(
                username="ingest-agent",
                mfa_authenticated=False,
                roles=["ingest_agent"],
                permissions={"logs:ingest"},
                is_super_admin=False,
            )
        else:
            logger.warning("Ingest agent token mismatch from request")
    if settings.ingest_token and bearer_token and hmac.compare_digest(bearer_token, settings.ingest_token):
        return AuthenticatedUser(
            username="ingest-agent",
            mfa_authenticated=False,
            roles=["ingest_agent"],
            permissions={"logs:ingest"},
            is_super_admin=False,
        )
    # Lab-only fallback: allow local/host-only ingestion when token is configured
    if settings.ingest_token and (
        client_ip in {settings.primary_asset_ip, "127.0.0.1", "localhost"}
        or client_ip.startswith("172.")
    ):
        return AuthenticatedUser(
            username="ingest-agent",
            mfa_authenticated=False,
            roles=["ingest_agent"],
            permissions={"logs:ingest"},
            is_super_admin=False,
        )
    if credentials:
        # Standard user auth path; may raise 401
        return get_current_user(credentials)
    return None
