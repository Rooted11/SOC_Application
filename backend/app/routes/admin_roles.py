from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..services.database import get_db, Role, RolePermission
from ..services.authz import require_permissions

router = APIRouter(prefix="/api/admin/roles", tags=["admin:roles"])


class RoleCreate(BaseModel):
    name: str
    description: str | None = ""
    permissions: List[str] = []
    built_in: bool | None = False


class RoleUpdate(BaseModel):
    description: str | None = None
    permissions: List[str] | None = None
    built_in: bool | None = None


@router.get("", dependencies=[Depends(require_permissions(["admin:roles"]))])
def list_roles(db: Session = Depends(get_db)):
    roles = db.query(Role).all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "permissions": [p.perm for p in r.permissions],
            "built_in": r.built_in,
        }
        for r in roles
    ]


@router.post("", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permissions(["admin:roles"]))])
def create_role(payload: RoleCreate, db: Session = Depends(get_db)):
    existing = db.query(Role).filter(Role.name == payload.name).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Role already exists")
    role = Role(
        name=payload.name,
        description=payload.description or "",
        built_in=bool(payload.built_in),
    )
    db.add(role)
    db.flush()
    for perm in payload.permissions:
        db.add(RolePermission(role_id=role.id, perm=perm))
    db.commit()
    return {"id": role.id, "name": role.name}


@router.patch("/{role_id}", dependencies=[Depends(require_permissions(["admin:roles"]))])
def update_role(role_id: int, payload: RoleUpdate, db: Session = Depends(get_db)):
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    if role.built_in and payload.permissions:
        # allow description change but protect perms for built-ins
        pass
    if payload.description is not None:
        role.description = payload.description
    if payload.built_in is not None:
        role.built_in = payload.built_in
    if payload.permissions is not None and not role.built_in:
        db.query(RolePermission).filter(RolePermission.role_id == role.id).delete()
        for perm in payload.permissions:
            db.add(RolePermission(role_id=role.id, perm=perm))
    db.commit()
    return {"id": role.id, "name": role.name}


@router.delete("/{role_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_permissions(["admin:roles"]))])
def delete_role(role_id: int, db: Session = Depends(get_db)):
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    if role.built_in:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete built-in role")
    db.query(RolePermission).filter(RolePermission.role_id == role.id).delete()
    db.delete(role)
    db.commit()
    return None
