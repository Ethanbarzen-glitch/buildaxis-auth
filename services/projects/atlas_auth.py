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

def _find_key(jwks: Dict[str, Any], kid: str) -> Optional[Dict[str, Any]]:
    for k in jwks.get("keys", []):
        if k.get("kid") == kid:
            return k
    return None

def decode_and_validate(token: str) -> Dict[str, Any]:
    try:
        header = jwt.get_unverified_header(token)
    except Exception as e:
        raise ValueError(f"bad header: {e}")
    kid = header.get("kid")
    if not kid:
        raise ValueError("token missing kid")

    jwks = fetch_jwks()
    key = _find_key(jwks, kid)
    if not key:
        jwks = fetch_jwks(force=True)
        key = _find_key(jwks, kid)
        if not key:
            raise ValueError(f"kid {kid} not found in JWKS")

    try:
        return jwt.decode(
            token,
            key,  # python-jose accepts JWK dict
            algorithms=["RS256"],
            audience=AUTH_AUDIENCE,
            issuer=AUTH_ISSUER,
        )
    except JWTError as e:
        raise ValueError(f"JWT validation failed: {e}")

def has_any_role(claims: Dict[str, Any], required: Iterable[str]) -> bool:
    return bool(set(claims.get("roles", [])) & set(required))
