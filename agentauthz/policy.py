"""Deterministic, deny-by-default policy at the tool-invocation boundary.

Every input to a decision comes from a verified token or from the
authoritative data store, never from the model's request. The model chooses
*which* tool to call and with *which* resource identifiers. Whether that call
is permitted is decided entirely here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

ACTIONS = ("read", "write", "irreversible")


@dataclass(frozen=True)
class ToolSpec:
    name: str
    resource: str  # audience URI an access token must be minted for
    required_scope: str
    action: str  # read | write | irreversible
    description: str = ""

    def __post_init__(self):
        if self.action not in ACTIONS:
            raise ValueError(f"action must be one of {ACTIONS}")


@dataclass
class Decision:
    effect: str  # allow | deny | approval_required
    reasons: list[str] = field(default_factory=list)
    checks: dict[str, bool] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.effect == "allow"


class PolicyDecisionPoint:
    def __init__(self, tools: list[ToolSpec]):
        self.tools = {t.name: t for t in tools}

    def decide(
        self,
        tool_name: str,
        access_claims: dict,
        caller_spiffe_id: str,
        resource_tenant: str | None,
    ) -> Decision:
        tool = self.tools.get(tool_name)
        if tool is None:
            return Decision("deny", [f"tool '{tool_name}' is not registered (deny by default)"],
                            {"tool_registered": False})

        scopes = set(str(access_claims.get("scope", "")).split())
        actor = (access_claims.get("act") or {}).get("sub")
        checks = {
            "tool_registered": True,
            "audience_matches_tool_resource": access_claims.get("aud") == tool.resource,
            "scope_granted": tool.required_scope in scopes,
            "token_bound_to_calling_agent": actor is not None and actor == caller_spiffe_id,
            "resource_exists": resource_tenant is not None,
            "tenant_matches": resource_tenant is not None and resource_tenant == access_claims.get("tenant"),
        }
        messages = {
            "audience_matches_tool_resource": f"token audience {access_claims.get('aud')!r} is not {tool.resource!r}",
            "scope_granted": f"scope '{tool.required_scope}' not granted (token has {sorted(scopes)})",
            "token_bound_to_calling_agent": f"token was issued to actor {actor!r}, but the caller is {caller_spiffe_id!r}",
            "resource_exists": "target resource does not exist",
            "tenant_matches": f"resource belongs to tenant {resource_tenant!r}, token is for {access_claims.get('tenant')!r}",
        }
        failed = [messages[name] for name, ok in checks.items() if not ok and name in messages]
        if not checks["resource_exists"]:
            failed.remove(messages["tenant_matches"])  # one reason is enough when the resource is missing
        if failed:
            return Decision("deny", failed, checks)
        if tool.action == "irreversible":
            return Decision("approval_required", ["irreversible action requires human approval"], checks)
        return Decision("allow", ["all checks passed"], checks)
