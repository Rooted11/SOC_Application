from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable, Set

from .database import SessionLocal, User, RolePermission, Role


@dataclass
class ResolvedUser:
    username: str
    roles: list[str]
    permissions: Set[str]
    is_super_admin: bool = False
    mfa_secret: str | None = None
    is_active: bool = True


def _derive_hash(password: str, salt_hex: str) -> str:
    salt_bytes = bytes.fromhex(salt_hex)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, 120000)
    return derived.hex()


def get_user(username: str) -> User | None:
    db = SessionLocal()
    try:
        return db.query(User).filter(User.username == username).first()
    finally:
        db.close()


def resolve_user(username: str) -> ResolvedUser | None:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username, User.is_active == True).first()
        if not user:
            return None
        roles = [ur.role.name for ur in user.roles if ur.role]
        perms = _collect_permissions(db, roles)
        return ResolvedUser(
            username=user.username,
            roles=roles,
            permissions=perms,
            is_super_admin="super_admin" in roles or "*" in perms,
            mfa_secret=user.mfa_secret,
            is_active=user.is_active,
        )
    finally:
        db.close()


def verify_user_credentials(username: str, password: str) -> ResolvedUser | None:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username, User.is_active == True).first()
        if not user or not user.password_salt or not user.password_hash:
            return None
        if _derive_hash(password, user.password_salt) != user.password_hash:
            return None
        roles = [ur.role.name for ur in user.roles if ur.role]
        perms = _collect_permissions(db, roles)
        return ResolvedUser(
            username=user.username,
            roles=roles,
            permissions=perms,
            is_super_admin="super_admin" in roles or "*" in perms,
            mfa_secret=user.mfa_secret,
            is_active=user.is_active,
        )
    finally:
        db.close()


def _collect_permissions(db, roles: Iterable[str]) -> Set[str]:
    if not roles:
        return set()
    q = (
        db.query(RolePermission.perm)
        .join(Role)
        .filter(Role.name.in_(roles))
    )
    return {p[0] for p in q.all()}


def load_permissions_for_roles(role_names: Iterable[str]) -> Set[str]:
    db = SessionLocal()
    try:
        if not role_names:
            return set()
        perms = (
            db.query(RolePermission.perm)
            .join(RolePermission.role)
            .filter(Role.name.in_(role_names))
            .all()
        )
        return {p[0] for p in perms}
    finally:
        db.close()


def has_permission(user: ResolvedUser, required: Iterable[str]) -> bool:
    if user.is_super_admin:
        return True
    perms = set(required)
    if not perms:
        return True
    for perm in perms:
        if perm in user.permissions or ("view:*" in user.permissions and perm.startswith("view")):
            continue
        return False
    return True
