"""Security token service implementing OAuth 2.0 Token Exchange (RFC 8693) semantics.

An agent presents:
  * subject_token: the user's token, which says who the agent acts for
  * actor_token:   the agent's own workload identity document
  * resource:      the target API (RFC 8707 resource indicator)
  * scope:         what it wants to do

The STS returns a short-lived access token whose audience is only that
resource. Its scope is the intersection of what the user holds, what the user
delegated to this agent, what the agent is registered for, and what the
resource accepts. It carries an ``act`` claim that records the delegation
chain. It never widens scope.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from .identity import WorkloadIdentityIssuer
from .tokens import SigningKey, TokenError, sign, verify

GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"
TOKEN_TYPE_ACCESS = "urn:ietf:params:oauth:token-type:access_token"


class ExchangeError(Exception):
    """OAuth error response. ``error`` uses RFC 6749 / RFC 8693 / RFC 8707 error codes."""

    def __init__(self, error: str, description: str):
        super().__init__(f"{error}: {description}")
        self.error = error
        self.description = description


class UserTokenIssuer:
    """Minimal identity provider that issues user (subject) tokens for the demo."""

    def __init__(self, issuer: str, key: SigningKey, audience: str, ttl: int = 3600):
        self.issuer, self.key, self.audience, self.ttl = issuer, key, audience, ttl

    def issue(self, user: str, tenant: str, scopes: set[str], now: float) -> str:
        return sign(
            {
                "iss": self.issuer,
                "sub": user,
                "aud": self.audience,
                "tenant": tenant,
                "scope": " ".join(sorted(scopes)),
                "iat": int(now),
                "exp": int(now) + self.ttl,
                "jti": uuid.uuid4().hex,
            },
            self.key,
        )


@dataclass
class DelegationRegistry:
    """Records which scopes each user has consented to delegate to each agent."""

    grants: dict[tuple[str, str], frozenset[str]] = field(default_factory=dict)

    def grant(self, user: str, agent_spiffe_id: str, scopes: set[str]) -> None:
        self.grants[(user, agent_spiffe_id)] = frozenset(scopes)

    def revoke(self, user: str, agent_spiffe_id: str) -> None:
        self.grants.pop((user, agent_spiffe_id), None)

    def granted(self, user: str, agent_spiffe_id: str) -> frozenset[str]:
        return self.grants.get((user, agent_spiffe_id), frozenset())


class SecurityTokenService:
    def __init__(
        self,
        issuer: str,
        key: SigningKey,
        idp: UserTokenIssuer,
        workloads: WorkloadIdentityIssuer,
        delegations: DelegationRegistry,
        resources: dict[str, set[str]],
        ttl: int = 300,
    ):
        self.issuer = issuer
        self.key = key
        self.idp = idp
        self.workloads = workloads
        self.delegations = delegations
        self.resources = {uri: frozenset(scopes) for uri, scopes in resources.items()}
        self.ttl = ttl

    def exchange(self, request: dict, now: float) -> dict:
        if request.get("grant_type") != GRANT_TOKEN_EXCHANGE:
            raise ExchangeError("unsupported_grant_type", "only token exchange is supported")
        for name, type_name in (("subject_token", "subject_token_type"), ("actor_token", "actor_token_type")):
            if not request.get(name):
                raise ExchangeError("invalid_request", f"{name} is required")
            if request.get(type_name) != TOKEN_TYPE_JWT:
                raise ExchangeError("invalid_request", f"{type_name} must be {TOKEN_TYPE_JWT}")

        resource = request.get("resource")
        if not resource:
            raise ExchangeError("invalid_target", "resource indicator (RFC 8707) is required")
        if resource not in self.resources:
            raise ExchangeError("invalid_target", f"unknown resource {resource!r}")

        try:
            subject = verify(request["subject_token"], [self.idp.key], now=now,
                             issuer=self.idp.issuer, audience=self.issuer)
        except TokenError as exc:
            raise ExchangeError("invalid_grant", f"subject_token rejected: {exc}") from exc
        try:
            actor = verify(request["actor_token"], [self.workloads.key], now=now,
                           issuer=self.workloads.issuer, audience=self.issuer)
        except TokenError as exc:
            raise ExchangeError("invalid_grant", f"actor_token rejected: {exc}") from exc

        agent = actor["sub"]
        registration = self.workloads.registry.get(agent)
        if registration is None:
            raise ExchangeError("unauthorized_client", f"{agent} is not a registered agent")

        requested = set(str(request.get("scope", "")).split())
        if not requested:
            raise ExchangeError("invalid_scope", "scope is required; agents must ask for specific permissions")
        ceilings = {
            "user holds": set(str(subject.get("scope", "")).split()),
            "user delegated to agent": set(self.delegations.granted(subject["sub"], agent)),
            "agent registration allows": set(registration.max_scopes),
            "resource accepts": set(self.resources[resource]),
        }
        missing = {name: sorted(requested - allowed) for name, allowed in ceilings.items() if requested - allowed}
        if missing:
            detail = "; ".join(f"not in '{name}': {scopes}" for name, scopes in missing.items())
            raise ExchangeError("invalid_scope", detail)

        act = {"sub": agent}
        if isinstance(subject.get("act"), dict):
            act["act"] = subject["act"]  # preserve prior actors (RFC 8693 section 4.1)
        exp = min(int(now) + self.ttl, int(subject["exp"]))
        claims = {
            "iss": self.issuer,
            "sub": subject["sub"],
            "aud": resource,
            "tenant": subject.get("tenant"),
            "scope": " ".join(sorted(requested)),
            "act": act,
            "iat": int(now),
            "exp": exp,
            "jti": uuid.uuid4().hex,
        }
        return {
            "access_token": sign(claims, self.key),
            "issued_token_type": TOKEN_TYPE_ACCESS,
            "token_type": "Bearer",
            "expires_in": exp - int(now),
            "scope": claims["scope"],
        }
