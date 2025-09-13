import os, time
from typing import Dict, Any, Optional, Iterable
import httpx
from jose import jwt, JWTError

AUTH_JWKS_URL = os.getenv("AUTH_JWKS_URL", "http://api:8000/.well-known/jwks.json")
AUTH_ISSUER   = os.getenv("AUTH_ISSUER", "buildaxis-auth")
AUTH_AUDIENCE = os.getenv("AUTH_AUDIENCE", "atlas-ai")
JWKS_TTL_SEC  = int(os.getenv("JWKS_TTL_SEC", "300"))

_cache_jwks: Optional[Dict[str, Any]] = None
_cache_expiry: float = 0.0

def _now() -> float: return time.time()

def fetch_jwks(force: bool = False) -> Dict[str, Any]:
    global _cache_jwks, _cache_expiry
    if not force and _cache_jwks and _now() < _cache_expiry:
        return _cache_jwks
    with httpx.Client(timeout=5.0) as client:
        resp = client.get(AUTH_JWKS_URL)
        resp.raise_for_status()
        _cache_jwks = resp.json()
        _cache_expiry = _now() + JWKS_TTL_SEC
        return _cache_jwks

def _find_key(jwks: Dict[str, Any], kid: Optional[str]) -> Optional[Dict[str, Any]]:
    keys = (jwks or {}).get("keys") or []
    if kid:
        for k in keys:
            if k.get("kid") == kid:
                return k
    return keys[0] if keys else None

def decode_and_validate(token: str) -> Dict[str, Any]:
    try:
        header = jwt.get_unverified_header(token)
    except Exception as e:
        raise JWTError(f"Bad token header: {e}")
    alg = header.get("alg", "RS256")
    kid = header.get("kid")

    jwks = fetch_jwks()
    key = _find_key(jwks, kid) or _find_key(fetch_jwks(force=True), kid)
    if key is None:
        raise JWTError("No matching JWK")

    return jwt.decode(
        token,
        key,
        algorithms=[alg],
        audience=AUTH_AUDIENCE,
        issuer=AUTH_ISSUER,
        options={"verify_aud": True},
    )

def has_any_role(claims: Dict[str, Any], required: Iterable[str]) -> bool:
    have = set(claims.get("roles", []) or [])
    need = set(required or [])
    return bool(have & need)

__all__ = ["decode_and_validate", "has_any_role", "fetch_jwks"]
