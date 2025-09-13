import os
from typing import Generator
from sqlalchemy import create_engine, Integer, String, Text, UniqueConstraint, text
from sqlalchemy.orm import sessionmaker, DeclarativeBase, Mapped, mapped_column, Session

DATABASE_URL = os.getenv("PROJECTS_DATABASE_URL", "postgresql+psycopg://auth:authpass@db:5432/auth")

engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

class Base(DeclarativeBase):
    pass

class Project(Base):
    __tablename__ = "projects"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    code: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    __table_args__ = (UniqueConstraint("code", name="uq_project_code"),)

def create_all() -> None:
    Base.metadata.create_all(bind=engine)

def apply_bootstrap_migrations() -> None:
    with engine.begin() as conn:
        # Remove dup rows by code (keep lowest id)
        conn.execute(text("""
            WITH ranked AS (
              SELECT id, code, ROW_NUMBER() OVER (PARTITION BY code ORDER BY id) rn
              FROM projects
            )
            DELETE FROM projects p USING ranked r
            WHERE p.id = r.id AND r.rn > 1;
        """))
        # Ensure DB-level uniqueness for code
        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ux_projects_code ON projects(code);"))

def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
