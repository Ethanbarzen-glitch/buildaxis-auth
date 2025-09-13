import os, time, json, logging
from datetime import datetime, timezone
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from db import engine, create_all, SessionLocal, seed_admin
from security import jwks
from auth_endpoints import router as auth_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("app")

app = FastAPI(title="BuildAxis Auth API", version="1.0.0")

allow_origins = [o.strip() for o in os.getenv("ALLOW_ORIGINS", "").split(",") if o.strip()]
if allow_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

def wait_for_db(timeout=60):
    start = time.time()
    while True:
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return
        except OperationalError:
            if time.time() - start > timeout:
                raise
            time.sleep(1)

@app.on_event("startup")
def on_startup():
    wait_for_db()
    create_all()
    with SessionLocal() as db:
        seed_admin(db)

@app.get("/health")
def health():
    ok = True
    try:
        with engine.connect() as c:
            c.execute(text("SELECT 1"))
    except Exception:
        ok = False
    return {"ok": True, "db_ok": ok, "time": datetime.now(timezone.utc).isoformat()}

@app.get("/.well-known/jwks.json")
def get_jwks():
    data = jwks()
    return Response(content=json.dumps(data), media_type="application/json",
                    headers={"Cache-Control": "public, max-age=300"})

app.include_router(auth_router)
