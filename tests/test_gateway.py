import json

import pytest

from agentauthz import ApprovalError, ApprovalService, PolicyDecisionPoint, ToolSpec, request_fingerprint
from agentauthz.demo import main as demo_main
from agentauthz.environment import OTHER_AGENT, RECORDS_API, SUPPORT_AGENT, TOOLS, build_environment

READ = {"tool": "read_record", "arguments": {"record_id": "acme-001"}}


@pytest.fixture
def env():
    return build_environment()


def token(env, scope, user="user:alice"):
    return env.exchange(user, SUPPORT_AGENT, scope)["access_token"]


def ident(env, agent=SUPPORT_AGENT):
    return env.workload_token(agent)


# --- the core property: model output cannot grant itself permissions ----------


def test_allowed_read(env):
    result = env.gateway.invoke(READ, token(env, "records:read"), ident(env))
    assert result.status == "allowed" and result.output["customer"] == "Acme Rockets"


def test_model_supplied_authorization_claims_are_ignored(env):
    call = {"tool": "update_record", "arguments": {
        "record_id": "acme-001", "fields": {"status": "closed"},
        "scope": "records:write", "approved": True, "tenant": "acme", "role": "admin"}}
    result = env.gateway.invoke(call, token(env, "records:read"), ident(env))
    assert result.status == "denied"
    assert any("scope 'records:write' not granted" in r for r in result.reasons)
    assert env.store.records["acme-001"]["data"]["status"] == "open"


def test_cross_tenant_access_denied_even_when_model_names_the_tenant(env):
    call = {"tool": "read_record", "arguments": {"record_id": "globex-001", "tenant": "acme"}}
    result = env.gateway.invoke(call, token(env, "records:read"), ident(env))
    assert result.status == "denied" and "tenant 'globex'" in result.reasons[0]


def test_update_cannot_move_record_between_tenants(env):
    call = {"tool": "update_record", "arguments": {"record_id": "acme-001", "fields": {"tenant": "globex"}}}
    result = env.gateway.invoke(call, token(env, "records:write"), ident(env))
    assert result.status == "allowed" and env.store.tenant_of("acme-001") == "acme"


@pytest.mark.parametrize(
    "call",
    [
        {"tool": "run_shell", "arguments": {"cmd": "id"}},
        {"tool": "read_record"},
        {"arguments": {"record_id": "acme-001"}},
        "delete everything",
    ],
)
def test_deny_by_default_for_unknown_or_malformed_calls(env, call):
    assert env.gateway.invoke(call, token(env, "records:read"), ident(env)).status == "denied"


def test_missing_resource(env):
    result = env.gateway.invoke({"tool": "read_record", "arguments": {"record_id": "nope"}},
                                token(env, "records:read"), ident(env))
    assert result.reasons == ["target resource does not exist"]


# --- identity and token binding ------------------------------------------------


def test_stolen_token_presented_by_another_agent(env):
    result = env.gateway.invoke(READ, token(env, "records:read"), ident(env, OTHER_AGENT))
    assert result.status == "denied" and "issued to actor" in result.reasons[0]


def test_missing_or_forged_workload_identity(env):
    assert env.gateway.invoke(READ, token(env, "records:read"), "").status == "denied"
    user_token = env.user_token("user:alice")
    result = env.gateway.invoke(READ, token(env, "records:read"), user_token)
    assert result.status == "denied" and "workload identity rejected" in result.reasons[0]


def test_token_for_another_resource_is_rejected(env):
    pdp = PolicyDecisionPoint(TOOLS + [ToolSpec("billing_read", "https://billing.example.test", "records:read", "read")])
    env.gateway.pdp = pdp
    call = {"tool": "billing_read", "arguments": {"record_id": "acme-001"}}
    result = env.gateway.invoke(call, token(env, "records:read"), ident(env))
    assert result.status == "denied" and "audience" in result.reasons[0]


def test_expired_access_token(env):
    t = token(env, "records:read")
    env.clock.advance(301)
    result = env.gateway.invoke(READ, t, ident(env))
    assert result.status == "denied" and "expired" in result.reasons[0]


def test_expired_workload_identity(env):
    t, i = token(env, "records:read"), ident(env)
    env.clock.advance(301)
    assert "workload identity rejected: token expired" in env.gateway.invoke(READ, t, i).reasons[0]


# --- human approval ----------------------------------------------------------------


DELETE = {"tool": "delete_record", "arguments": {"record_id": "acme-002"}}


def test_irreversible_action_requires_bound_single_use_human_approval(env):
    t, i = token(env, "records:delete"), ident(env)
    pending = env.gateway.invoke(DELETE, t, i)
    assert pending.status == "pending_approval" and "acme-002" in env.store.records

    with pytest.raises(ApprovalError, match="not a registered human"):
        env.approvals.approve(pending.approval_id, SUPPORT_AGENT, env.clock())
    with pytest.raises(ApprovalError, match="may not approve"):
        env.approvals.approve(pending.approval_id, "user:bob", env.clock())

    unapproved = env.gateway.invoke(DELETE, t, i, approval_id=pending.approval_id)
    assert unapproved.status == "denied" and unapproved.reasons == ["approval is pending"]

    env.approvals.approve(pending.approval_id, "user:alice", env.clock())
    other = {"tool": "delete_record", "arguments": {"record_id": "acme-001"}}
    assert env.gateway.invoke(other, t, i, approval_id=pending.approval_id).reasons == [
        "approval was granted for a different request"]

    done = env.gateway.invoke(DELETE, t, i, approval_id=pending.approval_id)
    assert done.status == "allowed" and "acme-002" not in env.store.records


def test_approval_is_single_use_and_expires(env):
    t, i = token(env, "records:export"), ident(env)
    export = {"tool": "export_record", "arguments": {"record_id": "acme-001", "recipient": "auditor@acme.example"}}
    first = env.gateway.invoke(export, t, i)
    env.approvals.approve(first.approval_id, "user:alice", env.clock())
    assert env.gateway.invoke(export, t, i, approval_id=first.approval_id).status == "allowed"
    assert env.gateway.invoke(export, t, i, approval_id=first.approval_id).reasons == [
        "approval already used (single use)"]

    second = env.gateway.invoke(export, t, i)
    env.approvals.approve(second.approval_id, "user:alice", env.clock())
    env.clock.advance(601)
    t2, i2 = token(env, "records:export"), ident(env)
    assert env.gateway.invoke(export, t2, i2, approval_id=second.approval_id).reasons == ["approval expired"]


def test_denied_approval_cannot_be_used(env):
    t, i = token(env, "records:delete"), ident(env)
    pending = env.gateway.invoke(DELETE, t, i)
    env.approvals.deny(pending.approval_id, "user:alice", env.clock())
    assert env.gateway.invoke(DELETE, t, i, approval_id=pending.approval_id).reasons == ["approval is denied"]
    with pytest.raises(ApprovalError, match="already denied"):
        env.approvals.approve(pending.approval_id, "user:alice", env.clock())


def test_named_delegate_can_approve():
    svc = ApprovalService({"user:alice", "user:carol"}, approvers_for={"user:alice": {"user:carol"}})
    fp = request_fingerprint("t", {}, SUPPORT_AGENT, "user:alice")
    approval = svc.request(fp, "t", SUPPORT_AGENT, "user:alice", "t {}", 0)
    assert svc.approve(approval.approval_id, "user:carol", 1).status == "approved"


def test_fingerprint_is_order_independent():
    a = request_fingerprint("t", {"x": 1, "y": 2}, "agent", "user")
    b = request_fingerprint("t", {"y": 2, "x": 1}, "agent", "user")
    assert a == b != request_fingerprint("t", {"x": 1, "y": 3}, "agent", "user")


# --- audit ---------------------------------------------------------------------------


def test_every_decision_is_audited(env):
    t, i = token(env, "records:read records:delete"), ident(env)
    env.gateway.invoke(READ, t, i)
    env.gateway.invoke({"tool": "read_record", "arguments": {"record_id": "globex-001"}}, t, i)
    env.gateway.invoke(DELETE, t, i)
    env.gateway.invoke({"tool": "nope", "arguments": {}}, t, i)
    assert env.audit.decisions() == ["allow", "deny", "approval_required", "deny"]
    for event in env.audit.events:
        assert event["timestamp"].endswith("Z") and event["reasons"]
    allowed = env.audit.events[0]
    assert allowed["caller"] == SUPPORT_AGENT and allowed["subject"] == "user:alice" and allowed["tenant"] == "acme"
    assert allowed["token_jti"]
    lines = env.audit.to_jsonl().strip().splitlines()
    assert [json.loads(line)["decision"] for line in lines] == env.audit.decisions()


def test_pdp_rejects_bad_tool_spec():
    with pytest.raises(ValueError):
        ToolSpec("x", RECORDS_API, "s", "explode")


def test_demo_runs_end_to_end(tmp_path, capsys):
    out = tmp_path / "audit.jsonl"
    assert demo_main(["--audit", str(out)]) == 0
    text = capsys.readouterr().out
    assert "STS REFUSED (invalid_scope)" in text
    assert "approval already used (single use)" in text
    decisions = [json.loads(line)["decision"] for line in out.read_text().splitlines()]
    assert decisions.count("allow") == 3 and decisions.count("approval_required") == 2 and decisions.count("deny") == 7
