import secrets
from typing import List, Set, Optional, Dict
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db import get_db, User, Role, RefreshToken, get_password_hash, verify_password, sha256
from security import create_access_token, now, has_role, decode_and_validate

REFRESH_DAYS = 30
router = APIRouter(tags=["auth"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class LoginBody(BaseModel):
    username: str
    password: str

class RefreshBody(BaseModel):
    refresh_token: str

def _roles(u: User) -> List[str]:
    return [r.name for r in u.roles]

def _issue_pair(u: User, db: Session) -> TokenPair:
    # rotate: invalidate existing refresh tokens for this user
    db.query(RefreshToken).filter(RefreshToken.user_id == u.id).delete(synchronize_session=False)
    rt = secrets.token_urlsafe(32)
    db.add(RefreshToken(
        user_id=u.id,
        token_hash=sha256(rt),
        created_at=now(),
        expires_at=now() + timedelta(days=REFRESH_DAYS),
    ))
    db.commit()
    acc = create_access_token(u.username, _roles(u))
    return TokenPair(access_token=acc, refresh_token=rt)

def _require_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    try:
        claims = decode_and_validate(token)
        sub = claims.get("sub")
        if not sub:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    u = db.query(User).filter_by(username=sub).one_or_none()
    if not u:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    return u

def _require_roles(required: Set[str]):
    def dep(u: User = Depends(_require_user)) -> User:
        if not has_role(set(_roles(u)), required):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
        return u
    return dep

@router.post("/token", response_model=TokenPair)
def token_form(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    u = db.query(User).filter_by(username=form.username).one_or_none()
    if not u or not verify_password(form.password, u.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    return _issue_pair(u, db)

@router.post("/token_json", response_model=TokenPair)
def token_json(body: LoginBody, db: Session = Depends(get_db)):
    u = db.query(User).filter_by(username=body.username).one_or_none()
    if not u or not verify_password(body.password, u.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    return _issue_pair(u, db)

@router.post("/token/refresh", response_model=TokenPair)
def refresh(body: RefreshBody, db: Session = Depends(get_db)):
    h = sha256(body.refresh_token)
    rt = db.query(RefreshToken).filter(RefreshToken.token_hash == h).one_or_none()
    if not rt or rt.expires_at < now() or rt.revoked_at is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid refresh token")
    u = db.query(User).filter(User.id == rt.user_id).one()
    # rotate: delete old token and issue new
    db.delete(rt); db.commit()
    return _issue_pair(u, db)

@router.post("/logout")
def logout(u: User = Depends(_require_user), db: Session = Depends(get_db)):
    db.query(RefreshToken).filter(RefreshToken.user_id == u.id).delete(synchronize_session=False)
    db.commit()
    return {"detail": "ok"}

@router.get("/auth/me")
def me(u: User = Depends(_require_user)):
    return {"username": u.username, "roles": _roles(u)}

class RegisterBody(BaseModel):
    username: str
    password: str

@router.post("/register")
def register(body: RegisterBody, db: Session = Depends(get_db)):
    if db.query(User).filter_by(username=body.username).one_or_none():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists")
    u = User(username=body.username, password_hash=get_password_hash(body.password))
    db.add(u); db.commit(); db.refresh(u)
    return {"ok": True, "username": u.username, "roles": _roles(u)}

@router.get("/auth/users")
def list_users(_: User = Depends(_require_roles({"admin"})), db: Session = Depends(get_db)):
    rows = db.query(User).all()
    return [{"username": r.username, "roles": [x.name for x in r.roles]} for r in rows]

@router.post("/auth/users/{username}/roles/{role}")
def grant_role(username: str, role: str, _: User = Depends(_require_roles({"admin"})), db: Session = Depends(get_db)):
    u = db.query(User).filter_by(username=username).one_or_none()
    if not u: raise HTTPException(status_code=404, detail="user not found")
    r = db.query(Role).filter_by(name=role).one_or_none()
    if not r:
        r = Role(name=role); db.add(r); db.flush()
    if r not in u.roles:
        u.roles.append(r)
    db.commit()
    return {"ok": True, "username": u.username, "roles": _roles(u)}
