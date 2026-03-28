"""
Authentication routes.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from ..services.config import settings
from ..services.rate_limit import login_rate_limiter
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


class LoginRequest(BaseModel):
    username: str
    password: str
    otp_code: str | None = None


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
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if is_mfa_enabled():
        if not payload.otp_code or not verify_totp_code(settings.auth_totp_secret or "", payload.otp_code):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Valid one-time code required.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    login_rate_limiter.reset(rate_limit_key)
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
