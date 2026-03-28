from __future__ import annotations

from fastapi import Depends, HTTPException, status

from .security import get_current_user, AuthenticatedUser


def require_permissions(perms: list[str] | tuple[str, ...]):
    async def _checker(user: AuthenticatedUser = Depends(get_current_user)):
        if user.is_super_admin:
            return user
        if not perms:
            return user
        allowed = any(
            (p in user.permissions) or ("*" in user.permissions)
            for p in perms
        )
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permissions: one of {', '.join(perms)} required",
            )
        return user

    return _checker


def require_roles(roles: list[str] | tuple[str, ...]):
    async def _checker(user: AuthenticatedUser = Depends(get_current_user)):
        if user.is_super_admin:
            return user
        if not any(r in user.roles for r in roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role",
            )
        return user

    return _checker
