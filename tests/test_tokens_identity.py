import base64
import json

import pytest

from agentauthz import IdentityError, SigningKey, SpiffeId, TokenError, WorkloadIdentityIssuer, sign, verify

NOW = 1_788_000_000


def claims(**overrides):
    base = {"iss": "https://iss.example.test", "aud": "https://api.example.test", "sub": "user:alice",
            "iat": NOW, "exp": NOW + 300}
    base.update(overrides)
    return base


def check(token, key, now=NOW, **kwargs):
    params = {"issuer": "https://iss.example.test", "audience": "https://api.example.test"}
    params.update(kwargs)
    return verify(token, [key], now=now, **params)


def test_round_trip():
    key = SigningKey.generate("k1")
    assert check(sign(claims(), key), key)["sub"] == "user:alice"


def test_audience_list_is_accepted():
    key = SigningKey.generate("k1")
    token = sign(claims(aud=["https://a.example.test", "https://api.example.test"]), key)
    assert check(token, key)["sub"] == "user:alice"


@pytest.mark.parametrize(
    "overrides,kwargs,message",
    [
        ({"exp": NOW - 1}, {}, "expired"),
        ({"iat": NOW + 60}, {}, "not yet valid"),
        ({"iss": "https://evil.example.test"}, {}, "issuer"),
        ({"aud": "https://other.example.test"}, {}, "audience"),
        ({"exp": None}, {}, "no expiry"),
    ],
)
def test_claim_validation(overrides, kwargs, message):
    key = SigningKey.generate("k1")
    with pytest.raises(TokenError, match=message):
        check(sign(claims(**overrides), key), key, **kwargs)


def test_wrong_key_and_unknown_kid():
    key, other = SigningKey.generate("k1"), SigningKey.generate("k1")
    with pytest.raises(TokenError, match="signature"):
        check(sign(claims(), other), key)
    with pytest.raises(TokenError, match="unknown key id"):
        check(sign(claims(), SigningKey.generate("k2")), key)


def _b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def test_tampered_claims_rejected():
    key = SigningKey.generate("k1")
    head, _, sig = sign(claims(), key).split(".")
    forged = f"{head}.{_b64(claims(sub='user:mallory'))}.{sig}"
    with pytest.raises(TokenError, match="signature"):
        check(forged, key)


def test_alg_none_rejected():
    key = SigningKey.generate("k1")
    token = f"{_b64({'alg': 'none', 'kid': 'k1'})}.{_b64(claims())}."
    with pytest.raises(TokenError, match="algorithm"):
        check(token, key)


@pytest.mark.parametrize("bad", ["", "a.b", "not-a-token", None])
def test_malformed_tokens(bad):
    with pytest.raises(TokenError):
        check(bad, SigningKey.generate("k1"))


def test_keys_are_random_per_generation():
    assert SigningKey.generate("k").secret != SigningKey.generate("k").secret


# --- SPIFFE IDs and workload identity ---------------------------------------


@pytest.mark.parametrize("value", ["spiffe://example.test/agents/support", "spiffe://prod.example-1.test/ns/a/sa/b"])
def test_valid_spiffe_ids(value):
    assert str(SpiffeId.parse(value)) == value


@pytest.mark.parametrize(
    "value",
    ["https://example.test/agents/a", "spiffe://", "spiffe://example.test", "spiffe://Example.test/a",
     "spiffe://example.test/a/../b", "spiffe://example.test/a//b", "spiffe://example.test/a?x=1",
     "spiffe://example.test/a#frag"],
)
def test_invalid_spiffe_ids(value):
    with pytest.raises(IdentityError):
        SpiffeId.parse(value)


def test_workload_issuer_only_issues_to_registered_agents_in_its_trust_domain():
    issuer = WorkloadIdentityIssuer("example.test", SigningKey.generate("svid"), ["https://gw.example.test"], ttl=60)
    issuer.register("spiffe://example.test/agents/a", "a", {"x:read"})
    with pytest.raises(IdentityError, match="outside trust domain"):
        issuer.register("spiffe://other.test/agents/b", "b", set())
    with pytest.raises(IdentityError, match="not a registered"):
        issuer.issue("spiffe://example.test/agents/unknown", NOW)
    doc = issuer.issue("spiffe://example.test/agents/a", NOW)
    got = verify(doc, [issuer.key], now=NOW + 30, issuer="spiffe://example.test", audience="https://gw.example.test")
    assert got["sub"] == "spiffe://example.test/agents/a" and got["exp"] == NOW + 60
