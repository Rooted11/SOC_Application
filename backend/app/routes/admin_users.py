from __future__ import annotations

import hashlib
import secrets
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..services.database import get_db, User, Role, UserRole
from ..services.authz import require_permissions

router = APIRouter(prefix="/api/admin/users", tags=["admin:users"])


class UserCreate(BaseModel):
    username: str
    password: str = Field(min_length=6)
    full_name: str | None = None
    email: str | None = None
    roles: List[str] = []


class UserUpdate(BaseModel):
    password: str | None = Field(default=None, min_length=6)
    full_name: str | None = None
    email: str | None = None
    roles: List[str] | None = None
    is_active: bool | None = None


def _hash_password(password: str) -> tuple[str, str]:
    salt = secrets.token_bytes(16)
    salt_hex = salt.hex()
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120000)
    return salt_hex, derived.hex()


@router.get("", dependencies=[Depends(require_permissions(["admin:users"]))])
def list_users(db: Session = Depends(get_db)):
    users = db.query(User).all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "full_name": u.full_name,
            "email": u.email,
            "roles": [ur.role.name for ur in u.roles if ur.role],
            "is_active": u.is_active,
            "created_at": u.created_at,
        }
        for u in users
    ]


@router.post("", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permissions(["admin:users"]))])
def create_user(payload: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == payload.username).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists")
    salt, pwd_hash = _hash_password(payload.password)
    user = User(
        username=payload.username,
        full_name=payload.full_name,
        email=payload.email,
        password_hash=pwd_hash,
        password_salt=salt,
        is_active=True,
    )
    db.add(user)
    db.flush()
    if payload.roles:
        roles = db.query(Role).filter(Role.name.in_(payload.roles)).all()
        for role in roles:
            db.add(UserRole(user_id=user.id, role_id=role.id))
    db.commit()
    return {"id": user.id, "username": user.username}


@router.patch("/{user_id}", dependencies=[Depends(require_permissions(["admin:users"]))])
def update_user(user_id: int, payload: UserUpdate, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if payload.password:
        user.password_salt, user.password_hash = _hash_password(payload.password)
    if payload.full_name is not None:
        user.full_name = payload.full_name
    if payload.email is not None:
        user.email = payload.email
    if payload.is_active is not None:
        user.is_active = payload.is_active
    if payload.roles is not None:
        db.query(UserRole).filter(UserRole.user_id == user.id).delete()
        roles = db.query(Role).filter(Role.name.in_(payload.roles)).all()
        for role in roles:
            db.add(UserRole(user_id=user.id, role_id=role.id))
    db.commit()
    return {"id": user.id, "username": user.username}


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_permissions(["admin:users"]))])
def delete_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    db.query(UserRole).filter(UserRole.user_id == user_id).delete()
    db.delete(user)
    db.commit()
    return None
