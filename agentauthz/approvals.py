"""Human approval for irreversible actions.

An approval is bound to a fingerprint of the exact request: the tool, the
canonicalized arguments, the calling agent, and the principal. It can be
granted only by a registered human who is that principal (or a named
delegate), it expires, and it can be used once.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass


def request_fingerprint(tool: str, arguments: dict, agent: str, subject: str) -> str:
    canonical = json.dumps({"tool": tool, "arguments": arguments, "agent": agent, "subject": subject},
                           sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass
class Approval:
    approval_id: str
    fingerprint: str
    tool: str
    agent: str
    subject: str
    summary: str
    created: float
    expires: float
    status: str = "pending"  # pending | approved | denied | used
    approver: str | None = None


class ApprovalError(Exception):
    pass


class ApprovalService:
    def __init__(self, human_approvers: set[str], ttl: int = 600, approvers_for: dict[str, set[str]] | None = None):
        self.human_approvers = set(human_approvers)
        self.ttl = ttl
        # By default only the principal the agent acts for may approve. approvers_for adds named delegates.
        self.approvers_for = {k: set(v) for k, v in (approvers_for or {}).items()}
        self.approvals: dict[str, Approval] = {}

    def request(self, fingerprint: str, tool: str, agent: str, subject: str, summary: str, now: float) -> Approval:
        approval = Approval(uuid.uuid4().hex[:12], fingerprint, tool, agent, subject, summary, now, now + self.ttl)
        self.approvals[approval.approval_id] = approval
        return approval

    def _pending(self, approval_id: str, now: float) -> Approval:
        approval = self.approvals.get(approval_id)
        if approval is None:
            raise ApprovalError("unknown approval id")
        if approval.status != "pending":
            raise ApprovalError(f"approval is already {approval.status}")
        if now > approval.expires:
            raise ApprovalError("approval request expired")
        return approval

    def approve(self, approval_id: str, approver: str, now: float) -> Approval:
        approval = self._pending(approval_id, now)
        if approver not in self.human_approvers:
            raise ApprovalError(f"{approver!r} is not a registered human approver")
        if approver == approval.agent:
            raise ApprovalError("an agent cannot approve its own action")
        if approver != approval.subject and approver not in self.approvers_for.get(approval.subject, set()):
            raise ApprovalError(f"{approver!r} may not approve actions taken on behalf of {approval.subject!r}")
        approval.status, approval.approver = "approved", approver
        return approval

    def deny(self, approval_id: str, approver: str, now: float) -> Approval:
        approval = self._pending(approval_id, now)
        if approver not in self.human_approvers:
            raise ApprovalError(f"{approver!r} is not a registered human approver")
        approval.status, approval.approver = "denied", approver
        return approval

    def consume(self, approval_id: str, fingerprint: str, now: float) -> tuple[bool, str]:
        approval = self.approvals.get(approval_id)
        if approval is None:
            return False, "unknown approval id"
        if approval.status == "used":
            return False, "approval already used (single use)"
        if approval.status != "approved":
            return False, f"approval is {approval.status}"
        if now > approval.expires:
            return False, "approval expired"
        if approval.fingerprint != fingerprint:
            return False, "approval was granted for a different request"
        approval.status = "used"
        return True, f"approved by {approval.approver}"
