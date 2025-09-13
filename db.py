import os, hashlib, datetime as dt
from typing import Generator
from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, ForeignKey, Table, UniqueConstraint, Index
)
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session
from passlib.context import CryptContext

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg://auth:authpass@db:5432/auth")
engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)
Base = declarative_base()

_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
def get_password_hash(p: str) -> str: return _pwd.hash(p)
def verify_password(p: str, h: str) -> bool: return _pwd.verify(p, h)
def sha256(s: str) -> str: return hashlib.sha256(s.encode("utf-8")).hexdigest()

user_roles = Table(
    "user_roles", Base.metadata,
    Column("user_id", ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    UniqueConstraint("user_id", "role_id", name="uq_user_role"),
)

class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.timezone.utc), nullable=False)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.timezone.utc), nullable=False)
    roles = relationship("Role", secondary=user_roles, lazy="joined")

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)  # sha256 hex
    created_at = Column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.timezone.utc), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    user = relationship("User")

Index("ix_refresh_valid", RefreshToken.user_id, RefreshToken.expires_at)

def create_all(): Base.metadata.create_all(bind=engine)

def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def seed_admin(db: Session):
    admin_user = os.getenv("ADMIN_USER", "admin")
    admin_pass = os.getenv("ADMIN_PASS", "adminpass")

    u = db.query(User).filter_by(username=admin_user).one_or_none()
    if u is None:
        u = User(username=admin_user, password_hash=get_password_hash(admin_pass))
        db.add(u)
    r_admin = db.query(Role).filter_by(name="admin").one_or_none()
    if r_admin is None:
        r_admin = Role(name="admin")
        db.add(r_admin)
    db.flush()
    if r_admin not in u.roles:
        u.roles.append(r_admin)
    db.commit()
