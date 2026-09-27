"""Agent workload identity.

SPIFFE IDs are parsed and validated according to the SPIFFE ID format
(spiffe://<trust-domain>/<path>). Identity *documents* here are HS256 JWTs
whose subject is a SPIFFE ID. They are an illustrative stand-in for a
JWT-SVID. There is no SPIRE server, no node or workload attestation, and no
asymmetric trust bundle. What the reference does demonstrate is the property
that matters at the tool boundary: every call carries a short-lived,
cryptographically verifiable workload identity that the gateway checks
itself, independently of anything the model says.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass

from .tokens import SigningKey, sign

_TRUST_DOMAIN = re.compile(r"^[a-z0-9._-]+$")
_SEGMENT = re.compile(r"^[A-Za-z0-9._-]+$")


class IdentityError(ValueError):
    pass


@dataclass(frozen=True)
class SpiffeId:
    trust_domain: str
    path: str

    @classmethod
    def parse(cls, value: str) -> "SpiffeId":
        if not isinstance(value, str) or not value.startswith("spiffe://"):
            raise IdentityError(f"{value!r} is not a spiffe:// URI")
        rest = value[len("spiffe://"):]
        trust_domain, _, path = rest.partition("/")
        if not trust_domain or not _TRUST_DOMAIN.match(trust_domain):
            raise IdentityError(f"invalid trust domain in {value!r}")
        if not path:
            raise IdentityError(f"{value!r} has no workload path")
        for segment in path.split("/"):
            if segment in ("", ".", "..") or not _SEGMENT.match(segment):
                raise IdentityError(f"invalid path segment {segment!r} in {value!r}")
        if "?" in value or "#" in value:
            raise IdentityError("SPIFFE IDs cannot contain query or fragment")
        return cls(trust_domain, "/" + path)

    def __str__(self) -> str:
        return f"spiffe://{self.trust_domain}{self.path}"


@dataclass(frozen=True)
class AgentRegistration:
    """What an agent is allowed to do, at most, regardless of who it acts for."""

    spiffe_id: SpiffeId
    display_name: str
    max_scopes: frozenset[str]


class WorkloadIdentityIssuer:
    """Issues short-lived identity documents to registered agents (illustrative JWT-SVID stand-in)."""

    def __init__(self, trust_domain: str, key: SigningKey, audiences: list[str], ttl: int = 300):
        self.trust_domain = trust_domain
        self.issuer = f"spiffe://{trust_domain}"
        self.key = key
        self.audiences = list(audiences)
        self.ttl = ttl
        self.registry: dict[str, AgentRegistration] = {}

    def register(self, spiffe_id: str, display_name: str, max_scopes: set[str]) -> AgentRegistration:
        sid = SpiffeId.parse(spiffe_id)
        if sid.trust_domain != self.trust_domain:
            raise IdentityError(f"{spiffe_id} is outside trust domain {self.trust_domain}")
        reg = AgentRegistration(sid, display_name, frozenset(max_scopes))
        self.registry[str(sid)] = reg
        return reg

    def issue(self, spiffe_id: str, now: float) -> str:
        if spiffe_id not in self.registry:
            raise IdentityError(f"{spiffe_id} is not a registered workload")
        claims = {
            "iss": self.issuer,
            "sub": spiffe_id,
            "aud": self.audiences,
            "iat": int(now),
            "exp": int(now) + self.ttl,
            "jti": uuid.uuid4().hex,
        }
        return sign(claims, self.key)
