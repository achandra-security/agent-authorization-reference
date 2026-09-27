"""Wires the components together into one synthetic environment, used by the demo and the tests.

Every key is generated fresh at startup. Nothing secret is stored in the repository.
"""

from __future__ import annotations

from dataclasses import dataclass

from .approvals import ApprovalService
from .audit import AuditLog
from .gateway import ToolGateway
from .identity import WorkloadIdentityIssuer
from .policy import PolicyDecisionPoint, ToolSpec
from .store import RecordStore
from .sts import GRANT_TOKEN_EXCHANGE, TOKEN_TYPE_JWT, DelegationRegistry, SecurityTokenService, UserTokenIssuer
from .tokens import SigningKey

TRUST_DOMAIN = "example.test"
STS_URI = "https://sts.example.test"
GATEWAY_URI = "https://tool-gateway.example.test"
IDP_URI = "https://idp.example.test"
RECORDS_API = "https://records.example.test"

SUPPORT_AGENT = f"spiffe://{TRUST_DOMAIN}/agents/support"
OTHER_AGENT = f"spiffe://{TRUST_DOMAIN}/agents/reporting"

ALL_SCOPES = frozenset({"records:read", "records:write", "records:delete", "records:export"})

TOOLS = [
    ToolSpec("read_record", RECORDS_API, "records:read", "read", "Read one record"),
    ToolSpec("update_record", RECORDS_API, "records:write", "write", "Update fields on a record"),
    ToolSpec("delete_record", RECORDS_API, "records:delete", "irreversible", "Permanently delete a record"),
    ToolSpec("export_record", RECORDS_API, "records:export", "irreversible",
             "Send a record to an external recipient (disclosure cannot be undone)"),
]


class ManualClock:
    def __init__(self, start: float = 1_788_000_000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@dataclass
class Environment:
    clock: ManualClock
    idp: UserTokenIssuer
    workloads: WorkloadIdentityIssuer
    delegations: DelegationRegistry
    sts: SecurityTokenService
    store: RecordStore
    approvals: ApprovalService
    audit: AuditLog
    gateway: ToolGateway

    def user_token(self, user: str) -> str:
        profile = USERS[user]
        return self.idp.issue(user, profile["tenant"], profile["scopes"], self.clock())

    def workload_token(self, spiffe_id: str) -> str:
        return self.workloads.issue(spiffe_id, self.clock())

    def exchange(self, user: str, agent: str, scope: str, resource: str = RECORDS_API) -> dict:
        return self.sts.exchange(
            {
                "grant_type": GRANT_TOKEN_EXCHANGE,
                "subject_token": self.user_token(user),
                "subject_token_type": TOKEN_TYPE_JWT,
                "actor_token": self.workload_token(agent),
                "actor_token_type": TOKEN_TYPE_JWT,
                "resource": resource,
                "scope": scope,
            },
            self.clock(),
        )


USERS = {
    "user:alice": {"tenant": "acme", "scopes": set(ALL_SCOPES)},
    "user:bob": {"tenant": "globex", "scopes": {"records:read"}},
}


def build_environment() -> Environment:
    clock = ManualClock()
    idp = UserTokenIssuer(IDP_URI, SigningKey.generate("idp-1"), audience=STS_URI)
    workloads = WorkloadIdentityIssuer(TRUST_DOMAIN, SigningKey.generate("svid-1"), [STS_URI, GATEWAY_URI])
    workloads.register(SUPPORT_AGENT, "support agent", set(ALL_SCOPES))
    workloads.register(OTHER_AGENT, "reporting agent", {"records:read"})

    delegations = DelegationRegistry()
    delegations.grant("user:alice", SUPPORT_AGENT, set(ALL_SCOPES))
    delegations.grant("user:bob", SUPPORT_AGENT, {"records:read"})

    sts_key = SigningKey.generate("sts-1")
    sts = SecurityTokenService(STS_URI, sts_key, idp, workloads, delegations,
                               resources={RECORDS_API: set(ALL_SCOPES)})

    store = RecordStore()
    store.add("acme-001", "acme", {"customer": "Acme Rockets", "status": "open"})
    store.add("acme-002", "acme", {"customer": "Acme Anvils", "status": "stale"})
    store.add("globex-001", "globex", {"customer": "Globex Corp", "status": "open"})

    approvals = ApprovalService(human_approvers={"user:alice", "user:bob"})
    audit = AuditLog()
    gateway = ToolGateway(GATEWAY_URI, PolicyDecisionPoint(TOOLS), STS_URI, sts_key, workloads,
                          store, approvals, audit, clock)
    return Environment(clock, idp, workloads, delegations, sts, store, approvals, audit, gateway)
