import pytest

from agentauthz import ExchangeError, verify
from agentauthz.environment import OTHER_AGENT, RECORDS_API, STS_URI, SUPPORT_AGENT, build_environment
from agentauthz.sts import GRANT_TOKEN_EXCHANGE, TOKEN_TYPE_ACCESS, TOKEN_TYPE_JWT


@pytest.fixture
def env():
    return build_environment()


def request(env, user="user:alice", agent=SUPPORT_AGENT, scope="records:read", resource=RECORDS_API, **overrides):
    req = {
        "grant_type": GRANT_TOKEN_EXCHANGE,
        "subject_token": env.user_token(user),
        "subject_token_type": TOKEN_TYPE_JWT,
        "actor_token": env.workload_token(agent),
        "actor_token_type": TOKEN_TYPE_JWT,
        "resource": resource,
        "scope": scope,
    }
    req.update(overrides)
    return req


def decode(env, response, resource=RECORDS_API):
    return verify(response["access_token"], [env.sts.key], now=env.clock(), issuer=STS_URI, audience=resource)


def test_successful_exchange_narrows_and_binds(env):
    response = env.sts.exchange(request(env, scope="records:read"), env.clock())
    assert response["issued_token_type"] == TOKEN_TYPE_ACCESS and response["token_type"] == "Bearer"
    claims = decode(env, response)
    assert claims["sub"] == "user:alice"
    assert claims["aud"] == RECORDS_API
    assert claims["scope"] == "records:read"
    assert claims["tenant"] == "acme"
    assert claims["act"] == {"sub": SUPPORT_AGENT}
    assert response["expires_in"] == 300


def test_scope_must_be_requested_explicitly(env):
    with pytest.raises(ExchangeError) as exc:
        env.sts.exchange(request(env, scope=""), env.clock())
    assert exc.value.error == "invalid_scope"


@pytest.mark.parametrize(
    "user,agent,scope,ceiling",
    [
        ("user:bob", SUPPORT_AGENT, "records:write", "user holds"),
        ("user:alice", OTHER_AGENT, "records:read", "user delegated to agent"),
        ("user:alice", SUPPORT_AGENT, "records:admin", "resource accepts"),
    ],
)
def test_scope_can_never_widen(env, user, agent, scope, ceiling):
    with pytest.raises(ExchangeError) as exc:
        env.sts.exchange(request(env, user=user, agent=agent, scope=scope), env.clock())
    assert exc.value.error == "invalid_scope" and ceiling in exc.value.description


def test_agent_registration_ceiling(env):
    env.delegations.grant("user:alice", OTHER_AGENT, {"records:read", "records:write"})
    with pytest.raises(ExchangeError) as exc:
        env.sts.exchange(request(env, agent=OTHER_AGENT, scope="records:write"), env.clock())
    assert "agent registration allows" in exc.value.description


def test_revoked_delegation(env):
    env.delegations.revoke("user:alice", SUPPORT_AGENT)
    with pytest.raises(ExchangeError, match="user delegated to agent"):
        env.sts.exchange(request(env), env.clock())


@pytest.mark.parametrize("resource,error", [(None, "invalid_target"), ("https://unknown.example.test", "invalid_target")])
def test_resource_indicator_required(env, resource, error):
    with pytest.raises(ExchangeError) as exc:
        env.sts.exchange(request(env, resource=resource), env.clock())
    assert exc.value.error == error


@pytest.mark.parametrize(
    "overrides,error",
    [
        ({"grant_type": "client_credentials"}, "unsupported_grant_type"),
        ({"actor_token": None}, "invalid_request"),
        ({"subject_token_type": "urn:ietf:params:oauth:token-type:saml2"}, "invalid_request"),
        ({"subject_token": "garbage"}, "invalid_grant"),
        ({"actor_token": "garbage"}, "invalid_grant"),
    ],
)
def test_malformed_requests(env, overrides, error):
    with pytest.raises(ExchangeError) as exc:
        env.sts.exchange(request(env, **overrides), env.clock())
    assert exc.value.error == error


def test_user_token_cannot_be_used_as_actor_token(env):
    with pytest.raises(ExchangeError) as exc:
        env.sts.exchange(request(env, actor_token=env.user_token("user:alice")), env.clock())
    assert exc.value.error == "invalid_grant"


def test_expired_subject_token(env):
    req = request(env)
    env.clock.advance(3601)
    req["actor_token"] = env.workload_token(SUPPORT_AGENT)
    with pytest.raises(ExchangeError, match="subject_token rejected: token expired"):
        env.sts.exchange(req, env.clock())


def test_issued_token_never_outlives_subject_token(env):
    req = request(env)
    env.clock.advance(3600 - 60)
    req["actor_token"] = env.workload_token(SUPPORT_AGENT)
    response = env.sts.exchange(req, env.clock())
    assert response["expires_in"] == 60


def test_prior_actor_chain_is_preserved(env):
    from agentauthz import sign

    subject = sign({"iss": env.idp.issuer, "sub": "user:alice", "aud": STS_URI, "tenant": "acme",
                    "scope": "records:read", "iat": int(env.clock()), "exp": int(env.clock()) + 600,
                    "act": {"sub": "spiffe://example.test/agents/orchestrator"}}, env.idp.key)
    claims = decode(env, env.sts.exchange(request(env, subject_token=subject), env.clock()))
    assert claims["act"] == {"sub": SUPPORT_AGENT, "act": {"sub": "spiffe://example.test/agents/orchestrator"}}
