"""
Authentication routes.
"""

import hashlib
import secrets
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..services.config import settings
from ..services.database import (
    AuditAction,
    AuditLog,
    PasswordResetToken,
    SessionLocal,
    User,
    get_db,
    hash_password,
)
from ..services.email import is_email_configured, send_password_reset_email
from ..services.rate_limit import login_rate_limiter, api_rate_limiter
from ..services.security import (
    AuthenticatedUser,
    authenticate_credentials,
    create_access_token,
    get_current_user,
    get_request_client_ip,
    is_mfa_enabled,
    verify_totp_code,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

RESET_TOKEN_BYTES = 32


def _audit_login(username: str, success: bool, reason: str, request: Request) -> None:
    """Write a login attempt to the audit log table."""
    try:
        db = SessionLocal()
        entry = AuditLog(
            actor=username or "unknown",
            actor_roles=[],
            action=AuditAction.login,
            entity_type="user",
            entity_id=username or "unknown",
            ip_address=get_request_client_ip(request),
            details={"success": success, "reason": reason},
            created_at=datetime.utcnow(),
        )
        db.add(entry)
        db.commit()
        db.close()
    except Exception:
        pass  # never let audit failures break login


class LoginRequest(BaseModel):
    username: str
    password: str
    otp_code: str | None = None


class ForgotPasswordRequest(BaseModel):
    username: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=8)


def _hash_reset_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _login_rate_limit_key(request: Request, username: str) -> str:
    client_ip = get_request_client_ip(request)
    return f"{client_ip}:{username.strip().lower() or 'unknown'}"


@router.get("/status")
def auth_status():
    return {
        "auth_enabled": settings.auth_enabled,
        "mfa_enabled": is_mfa_enabled(),
        "token_ttl_minutes": settings.auth_token_ttl_minutes,
        "roles": ["super_admin"] if not settings.auth_enabled else [],
        "permissions": ["*"] if not settings.auth_enabled else [],
    }


@router.post("/login")
def login(payload: LoginRequest, request: Request):
    if not settings.auth_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authentication is disabled for this environment.",
        )

    rate_limit_key = _login_rate_limit_key(request, payload.username)
    if settings.rate_limit_enabled:
        rate_limit = login_rate_limiter.check(
            rate_limit_key,
            limit=settings.login_rate_limit_attempts,
            window_seconds=settings.login_rate_limit_window_seconds,
        )
        if not rate_limit.allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many login attempts. Try again later.",
                headers={"Retry-After": str(rate_limit.retry_after_seconds)},
            )

    if not authenticate_credentials(payload.username, payload.password):
        _audit_login(payload.username, False, "bad_credentials", request)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if is_mfa_enabled():
        if not payload.otp_code or not verify_totp_code(settings.auth_totp_secret or "", payload.otp_code):
            _audit_login(payload.username, False, "bad_totp", request)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Valid one-time code required.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    login_rate_limiter.reset(rate_limit_key)
    _audit_login(payload.username, True, "ok", request)
    return {
        "access_token": create_access_token(
            payload.username,
            mfa_authenticated=is_mfa_enabled(),
        ),
        "token_type": "bearer",
        "username": payload.username,
        "mfa_authenticated": is_mfa_enabled(),
        "expires_in": settings.auth_token_ttl_minutes * 60,
    }


@router.get("/me")
def me(user: AuthenticatedUser = Depends(get_current_user)):
    return {
        "auth_enabled": settings.auth_enabled,
        "mfa_enabled": is_mfa_enabled(),
        "username": user.username,
        "mfa_authenticated": user.mfa_authenticated,
        "roles": user.roles,
        "permissions": list(user.permissions),
    }


_GENERIC_RESET_RESPONSE = {
    "message": "If that account exists and has an email on file, a reset link has been sent."
}


@router.post("/forgot-password")
def forgot_password(payload: ForgotPasswordRequest, request: Request, db: Session = Depends(get_db)):
    if not settings.auth_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authentication is disabled for this environment.",
        )

    rate_limit_key = f"forgot-password:{get_request_client_ip(request)}"
    if settings.rate_limit_enabled:
        rate_limit = api_rate_limiter.check(rate_limit_key, limit=5, window_seconds=300)
        if not rate_limit.allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many reset requests. Try again later.",
                headers={"Retry-After": str(rate_limit.retry_after_seconds)},
            )

    user = db.query(User).filter(User.username == payload.username.strip()).first()
    if user and user.is_active and user.email and is_email_configured():
        raw_token = secrets.token_urlsafe(RESET_TOKEN_BYTES)
        expires_at = datetime.utcnow() + timedelta(minutes=settings.password_reset_ttl_minutes)
        db.add(
            PasswordResetToken(
                user_id=user.id,
                token_hash=_hash_reset_token(raw_token),
                expires_at=expires_at,
            )
        )
        db.commit()

        reset_url = f"{settings.frontend_url.rstrip('/')}/reset-password?token={raw_token}"
        send_password_reset_email(
            to=user.email,
            username=user.username,
            reset_url=reset_url,
            ttl_minutes=settings.password_reset_ttl_minutes,
        )

    # Always return the same response so we don't leak which usernames exist.
    return _GENERIC_RESET_RESPONSE


@router.post("/reset-password")
def reset_password(payload: ResetPasswordRequest, db: Session = Depends(get_db)):
    if not settings.auth_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authentication is disabled for this environment.",
        )

    token_hash = _hash_reset_token(payload.token)
    reset_token = (
        db.query(PasswordResetToken)
        .filter(PasswordResetToken.token_hash == token_hash)
        .first()
    )

    if (
        not reset_token
        or reset_token.used_at is not None
        or reset_token.expires_at < datetime.utcnow()
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This reset link is invalid or has expired.",
        )

    user = db.query(User).filter(User.id == reset_token.user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="This reset link is invalid.")

    user.password_salt, user.password_hash = hash_password(payload.new_password)
    reset_token.used_at = datetime.utcnow()
    db.commit()

    return {"message": "Password has been reset. You can now sign in with your new password."}
