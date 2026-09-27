"""agentauthz: reference architecture for deterministic authorization at the agent tool boundary."""

from .approvals import ApprovalError, ApprovalService, request_fingerprint
from .audit import AuditLog
from .gateway import GatewayResult, ToolGateway
from .identity import IdentityError, SpiffeId, WorkloadIdentityIssuer
from .policy import Decision, PolicyDecisionPoint, ToolSpec
from .sts import DelegationRegistry, ExchangeError, SecurityTokenService, UserTokenIssuer
from .tokens import SigningKey, TokenError, sign, verify

__version__ = "0.1.0"

__all__ = [
    "ApprovalError", "ApprovalService", "AuditLog", "Decision", "DelegationRegistry", "ExchangeError",
    "GatewayResult", "IdentityError", "PolicyDecisionPoint", "SecurityTokenService", "SigningKey",
    "SpiffeId", "TokenError", "ToolGateway", "ToolSpec", "UserTokenIssuer", "WorkloadIdentityIssuer",
    "request_fingerprint", "sign", "verify", "__version__",
]
