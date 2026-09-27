"""Policy enforcement point in front of agent tools.

    tool call (from model output: untrusted)
        -> verify caller workload identity   (who is calling)
        -> resolve tool from registry         (deny unknown tools)
        -> verify access token                (issuer, signature, expiry, audience = tool resource)
        -> resolve resource owner from store  (never from the model's arguments)
        -> policy decision                    (scope, actor binding, tenant)
        -> human approval if irreversible     (bound to the exact request, single use)
        -> execute, and write an audit event for every outcome
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .approvals import ApprovalService, request_fingerprint
from .audit import AuditLog
from .identity import WorkloadIdentityIssuer
from .policy import PolicyDecisionPoint
from .store import TOOL_IMPLEMENTATIONS, RecordStore
from .tokens import SigningKey, TokenError, verify


@dataclass
class GatewayResult:
    status: str  # allowed | denied | pending_approval
    reasons: list[str]
    output: dict | None = None
    approval_id: str | None = None
    checks: dict = field(default_factory=dict)


class ToolGateway:
    def __init__(
        self,
        audience: str,
        pdp: PolicyDecisionPoint,
        sts_issuer: str,
        sts_key: SigningKey,
        workloads: WorkloadIdentityIssuer,
        store: RecordStore,
        approvals: ApprovalService,
        audit: AuditLog,
        clock: Callable[[], float],
    ):
        self.audience = audience
        self.pdp = pdp
        self.sts_issuer = sts_issuer
        self.sts_key = sts_key
        self.workloads = workloads
        self.store = store
        self.approvals = approvals
        self.audit = audit
        self.clock = clock

    def _finish(self, now, status, reasons, ctx, output=None, approval_id=None, checks=None) -> GatewayResult:
        decision = {"allowed": "allow", "denied": "deny", "pending_approval": "approval_required"}[status]
        self.audit.record(now, decision=decision, reasons=reasons, approval_id=approval_id, **ctx)
        return GatewayResult(status, reasons, output, approval_id, checks or {})

    def invoke(self, call: dict, access_token: str, workload_token: str, approval_id: str | None = None) -> GatewayResult:
        now = self.clock()
        tool_name = call.get("tool") if isinstance(call, dict) else None
        arguments = call.get("arguments") if isinstance(call, dict) else None
        ctx = {"tool": tool_name, "caller": None, "subject": None, "tenant": None, "token_jti": None,
               "resource_id": arguments.get("record_id") if isinstance(arguments, dict) else None}
        if not isinstance(tool_name, str) or not isinstance(arguments, dict):
            return self._finish(now, "denied", ["malformed tool call"], ctx)

        # 1. Who is calling? Verified workload identity, not a name the model supplied.
        try:
            identity = verify(workload_token, [self.workloads.key], now=now,
                              issuer=self.workloads.issuer, audience=self.audience)
        except TokenError as exc:
            return self._finish(now, "denied", [f"workload identity rejected: {exc}"], ctx)
        caller = identity["sub"]
        ctx["caller"] = caller

        # 2. Unknown tools are denied before any token is even examined.
        tool = self.pdp.tools.get(tool_name)
        if tool is None:
            return self._finish(now, "denied", [f"tool '{tool_name}' is not registered (deny by default)"], ctx)

        # 3. The access token must be valid for *this tool's* resource.
        try:
            claims = verify(access_token, [self.sts_key], now=now, issuer=self.sts_issuer, audience=tool.resource)
        except TokenError as exc:
            return self._finish(now, "denied", [f"access token rejected: {exc}"], ctx)
        ctx.update(subject=claims.get("sub"), tenant=claims.get("tenant"), token_jti=claims.get("jti"))

        # 4. Ownership comes from the store. Any tenant, owner, or "approved" field in arguments is ignored.
        resource_tenant = self.store.tenant_of(arguments.get("record_id"))
        decision = self.pdp.decide(tool_name, claims, caller, resource_tenant)
        if decision.effect == "deny":
            return self._finish(now, "denied", decision.reasons, ctx, checks=decision.checks)

        # 5. Irreversible actions need a human approval bound to exactly this request.
        if decision.effect == "approval_required":
            fingerprint = request_fingerprint(tool_name, arguments, caller, claims["sub"])
            if approval_id is None:
                pending = self.approvals.request(fingerprint, tool_name, caller, claims["sub"],
                                                 f"{tool_name} {arguments}", now)
                return self._finish(now, "pending_approval", decision.reasons, ctx,
                                    approval_id=pending.approval_id, checks=decision.checks)
            ok, why = self.approvals.consume(approval_id, fingerprint, now)
            if not ok:
                return self._finish(now, "denied", [why], ctx, approval_id=approval_id, checks=decision.checks)
            decision.reasons = ["all checks passed", why]

        # 6. Execute.
        output = TOOL_IMPLEMENTATIONS[tool_name](self.store, arguments)
        return self._finish(now, "allowed", decision.reasons, ctx, output=output,
                            approval_id=approval_id, checks=decision.checks)
