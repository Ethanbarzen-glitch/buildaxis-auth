import os, base64, secrets, json
from typing import Any, List, Optional, Set, Dict
from datetime import datetime, timedelta, timezone

from jose import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes

ISSUER     = os.getenv("JWT_ISSUER", "buildaxis-auth")
AUDIENCE   = os.getenv("JWT_AUDIENCE", "atlas-ai")
ACCESS_MIN = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
KEY_DIR    = os.getenv("KEY_DIR", "/app/keys")

os.makedirs(KEY_DIR, exist_ok=True)
PRIV_PATH = os.path.join(KEY_DIR, "private.pem")
PUB_PATH  = os.path.join(KEY_DIR, "public.pem")
KID_PATH  = os.path.join(KEY_DIR, "kid.txt")

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _ensure_rsa() -> None:
    if os.path.exists(PRIV_PATH) and os.path.exists(PUB_PATH) and os.path.exists(KID_PATH):
        return
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = key.public_key()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    spki_der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256()); digest.update(spki_der)
    kid = digest.finalize()[:8].hex()

    with open(PRIV_PATH, "wb") as f: f.write(priv_pem)
    with open(PUB_PATH,  "wb") as f: f.write(pub_pem)
    with open(KID_PATH,  "w")  as f: f.write(kid)

# initialize key material
_ensure_rsa()
with open(PRIV_PATH, "rb") as f: _priv = f.read()   # PEM (bytes)
with open(PUB_PATH,  "rb") as f: _pub  = f.read()
with open(KID_PATH,  "r")  as f: _kid  = f.read().strip()

def now() -> datetime:
    return datetime.now(timezone.utc)

def create_access_token(subject: str, roles: List[str], minutes: Optional[int] = None) -> str:
    exp_min = minutes if minutes is not None else ACCESS_MIN
    iat = now()
    payload: Dict[str, Any] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": subject,
        "iat": int(iat.timestamp()),
        "nbf": int(iat.timestamp()),
        "exp": int((iat + timedelta(minutes=exp_min)).timestamp()),
        "jti": secrets.token_hex(12),
        "roles": roles or [],
    }
    return jwt.encode(payload, _priv, algorithm="RS256", headers={"kid": _kid})

def jwks() -> Dict[str, Any]:
    pub = serialization.load_pem_public_key(_pub)
    numbers = pub.public_numbers()
    n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    return {"keys": [{
        "kty": "RSA", "use": "sig", "kid": _kid, "alg": "RS256",
        "n": _b64url(n), "e": _b64url(e),
    }]}

def decode_and_validate(token: str) -> Dict[str, Any]:
    # validate signature + claims using public key
    return jwt.decode(token, _pub, algorithms=["RS256"], audience=AUDIENCE, issuer=ISSUER)

def has_role(user_roles: Set[str], required: Set[str]) -> bool:
    return bool(user_roles & required)
