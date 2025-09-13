from typing import Dict, Any, Optional, Set
from fastapi import FastAPI, Header, HTTPException, status, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from sqlalchemy import select

from db import get_db, create_all, Team
from atlas_auth import decode_and_validate, has_any_role

app = FastAPI(title="Teams Service", version="0.1.0")
create_all()

class TeamIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    code: str = Field(min_length=1, max_length=64)
    description: Optional[str] = None

class TeamUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = None

def require_auth(required_roles: Optional[Set[str]] = None):
    def _dep(authorization: str = Header(None, alias="Authorization")) -> Dict[str, Any]:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
        token = authorization.split(" ", 1)[1]
        claims = decode_and_validate(token)
        if required_roles and not has_any_role(claims, required_roles):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return claims
    return _dep

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/me")
def me(claims: Dict[str, Any] = Depends(require_auth())):
    return {"sub": claims.get("sub"), "roles": claims.get("roles", [])}

@app.get("/teams")
def list_teams(
    q: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    _claims: Dict[str, Any] = Depends(require_auth())
):
    stmt = select(Team)
    if q:
        q_like = f"%{q}%"
        stmt = stmt.where((Team.name.ilike(q_like)) | (Team.code.ilike(q_like)))
    stmt = stmt.order_by(Team.id.asc()).limit(limit).offset(offset)
    rows = db.execute(stmt).scalars().all()
    items = [{"id": r.id, "name": r.name, "code": r.code, "description": r.description} for r in rows]
    return {"items": items, "count": len(items)}

@app.post("/teams", status_code=201)
def create_team(
    payload: TeamIn,
    db: Session = Depends(get_db),
    _claims: Dict[str, Any] = Depends(require_auth({"admin"}))
):
    row = Team(name=payload.name, code=payload.code, description=payload.description)
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Team code already exists")
    db.refresh(row)
    return {"id": row.id, "name": row.name, "code": row.code, "description": row.description}

@app.get("/teams/{code}")
def get_team(code: str, db: Session = Depends(get_db), _claims: Dict[str, Any] = Depends(require_auth())):
    row = db.execute(select(Team).where(Team.code == code)).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    return {"id": row.id, "name": row.name, "code": row.code, "description": row.description}

@app.put("/teams/{code}")
def update_team(
    code: str,
    patch: TeamUpdate,
    db: Session = Depends(get_db),
    _claims: Dict[str, Any] = Depends(require_auth({"admin"}))
):
    row = db.execute(select(Team).where(Team.code == code)).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    if patch.name is not None:
        row.name = patch.name
    if patch.description is not None:
        row.description = patch.description
    db.commit()
    db.refresh(row)
    return {"id": row.id, "name": row.name, "code": row.code, "description": row.description}

@app.delete("/teams/{code}")
def delete_team(code: str, db: Session = Depends(get_db), _claims: Dict[str, Any] = Depends(require_auth({"admin"}))):
    row = db.execute(select(Team).where(Team.code == code)).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    db.delete(row)
    db.commit()
    return {"ok": True, "deleted": 1}
