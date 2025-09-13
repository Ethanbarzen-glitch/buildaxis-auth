from typing import Dict, Any, Optional, Set
from fastapi import FastAPI, Header, HTTPException, status, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from sqlalchemy import or_

from db import get_db, create_all, apply_bootstrap_migrations, Project
from atlas_auth import decode_and_validate, has_any_role

app = FastAPI(title="Projects Service", version="0.4.0")

# Initialize schema & constraints
create_all()
apply_bootstrap_migrations()

class ProjectIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    code: str = Field(min_length=1, max_length=64)
    description: Optional[str] = None

class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = None

def require_auth(required_roles: Optional[Set[str]] = None):
    def _dep(authorization: str = Header(None, alias="Authorization")) -> Dict[str, Any]:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
        token = authorization.split(" ", 1)[1]
        try:
            claims = decode_and_validate(token)
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {e}")
        if required_roles and not has_any_role(claims, required_roles):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return claims
    return _dep

@app.get("/health")
def health(): return {"ok": True}

@app.get("/me")
def me(claims: Dict[str, Any] = Depends(require_auth())):
    return {"sub": claims.get("sub"), "roles": claims.get("roles", [])}

@app.get("/projects")
def list_projects(
    q: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    claims: Dict[str, Any] = Depends(require_auth()),
    db: Session = Depends(get_db),
):
    query = db.query(Project)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Project.name.ilike(like), Project.code.ilike(like)))
    rows = query.order_by(Project.id.asc()).limit(limit).offset(offset).all()
    items = [{"id": r.id, "name": r.name, "code": r.code, "description": r.description} for r in rows]
    return {"items": items, "count": len(items)}

@app.get("/projects/{code}")
def get_project(code: str, claims: Dict[str, Any] = Depends(require_auth()), db: Session = Depends(get_db)):
    row = db.query(Project).filter(Project.code == code).one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    return {"id": row.id, "name": row.name, "code": row.code, "description": row.description}

@app.post("/projects")
def create_project(
    body: ProjectIn,
    claims: Dict[str, Any] = Depends(require_auth(required_roles={"admin"})),
    db: Session = Depends(get_db),
):
    try:
        if db.query(Project).filter(Project.code == body.code).one_or_none():
            raise HTTPException(status_code=409, detail="Project code already exists")
        row = Project(name=body.name, code=body.code, description=body.description)
        db.add(row)
        db.commit()
        db.refresh(row)
        return {"id": row.id, "name": row.name, "code": row.code, "description": row.description}
    except IntegrityError:
        db.rollback()
        # Race-safe 409
        raise HTTPException(status_code=409, detail="Project code already exists")

@app.put("/projects/{code}")
def update_project(
    code: str,
    body: ProjectUpdate,
    claims: Dict[str, Any] = Depends(require_auth(required_roles={"admin"})),
    db: Session = Depends(get_db),
):
    row = db.query(Project).filter(Project.code == code).one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    if body.name is not None:
        row.name = body.name
    if body.description is not None:
        row.description = body.description
    db.commit()
    db.refresh(row)
    return {"id": row.id, "name": row.name, "code": row.code, "description": row.description}

@app.delete("/projects/{code}")
def delete_project(
    code: str,
    claims: Dict[str, Any] = Depends(require_auth(required_roles={"admin"})),
    db: Session = Depends(get_db),
):
    row = db.query(Project).filter(Project.code == code).one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    db.delete(row)
    db.commit()
    return {"ok": True, "deleted": 1}
