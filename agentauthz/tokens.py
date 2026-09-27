"""Compact JWS (HS256) tokens using only the standard library.

This is a real, verifiable JWT implementation (RFC 7519 claims, RFC 7515
compact serialization, HMAC-SHA256). It is deliberately small, and it uses
symmetric keys so the reference runs with no dependencies. A production
deployment would use asymmetric keys (for example ES256) published through
JWKS, so that verifiers never hold signing material.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from typing import Any, Iterable


class TokenError(Exception):
    """Token failed verification. The message states the specific reason."""


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + padding)
    except (ValueError, TypeError) as exc:
        raise TokenError("malformed base64url segment") from exc


@dataclass(frozen=True)
class SigningKey:
    kid: str
    secret: bytes

    @classmethod
    def generate(cls, kid: str) -> "SigningKey":
        """Generate a fresh random key. Keys are never committed to the repository."""
        return cls(kid=kid, secret=secrets.token_bytes(32))


def sign(claims: dict[str, Any], key: SigningKey) -> str:
    header = {"alg": "HS256", "typ": "JWT", "kid": key.kid}
    signing_input = f"{_b64e(json.dumps(header, separators=(',', ':')).encode())}." \
                    f"{_b64e(json.dumps(claims, separators=(',', ':'), sort_keys=True).encode())}"
    sig = hmac.new(key.secret, signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{_b64e(sig)}"


def unverified_header(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenError("token must have three segments")
    try:
        return json.loads(_b64d(parts[0]))
    except json.JSONDecodeError as exc:
        raise TokenError("malformed header") from exc


def verify(
    token: str,
    keys: Iterable[SigningKey],
    *,
    now: float,
    issuer: str,
    audience: str,
    leeway: int = 0,
) -> dict[str, Any]:
    """Verify signature, algorithm, issuer, audience, and time claims. Returns the claims."""
    if not isinstance(token, str) or not token:
        raise TokenError("no token presented")
    header = unverified_header(token)
    if header.get("alg") != "HS256":
        raise TokenError(f"algorithm {header.get('alg')!r} not accepted")
    key = next((k for k in keys if k.kid == header.get("kid")), None)
    if key is None:
        raise TokenError(f"unknown key id {header.get('kid')!r}")
    head_b64, body_b64, sig_b64 = token.split(".")
    expected = hmac.new(key.secret, f"{head_b64}.{body_b64}".encode("ascii"), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, _b64d(sig_b64)):
        raise TokenError("signature verification failed")
    try:
        claims = json.loads(_b64d(body_b64))
    except json.JSONDecodeError as exc:
        raise TokenError("malformed claims") from exc
    if claims.get("iss") != issuer:
        raise TokenError(f"issuer {claims.get('iss')!r} is not the expected {issuer!r}")
    aud = claims.get("aud")
    audiences = aud if isinstance(aud, list) else [aud]
    if audience not in audiences:
        raise TokenError(f"audience {aud!r} does not include {audience!r}")
    exp, nbf = claims.get("exp"), claims.get("nbf", claims.get("iat"))
    if not isinstance(exp, (int, float)):
        raise TokenError("token has no expiry")
    if now > exp + leeway:
        raise TokenError("token expired")
    if isinstance(nbf, (int, float)) and now + leeway < nbf:
        raise TokenError("token not yet valid")
    return claims
