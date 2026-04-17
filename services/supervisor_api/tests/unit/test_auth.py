import pytest
from supervisor_api.auth import decode_jwt_unverified, sign_jwt, verify_jwt


def test_sign_and_verify_roundtrip():
    tok = sign_jwt({"sub": "app1", "scopes": ["refund"]}, secret="s")
    claims = verify_jwt(tok, "s")
    assert claims["sub"] == "app1"
    assert claims["scopes"] == ["refund"]


def test_verify_rejects_bad_signature():
    tok = sign_jwt({"sub": "app1"}, secret="good")
    with pytest.raises(ValueError, match="bad signature"):
        verify_jwt(tok, "evil")


def test_verify_rejects_expired():
    tok = sign_jwt({"sub": "app1", "exp": 1}, secret="s")
    with pytest.raises(ValueError, match="expired"):
        verify_jwt(tok, "s")


def test_decode_unverified_extracts_claims_without_secret():
    tok = sign_jwt({"sub": "app-x"}, secret="s")
    assert decode_jwt_unverified(tok)["sub"] == "app-x"


def test_malformed_token_raises():
    with pytest.raises(ValueError):
        verify_jwt("not-a-jwt", "s")
