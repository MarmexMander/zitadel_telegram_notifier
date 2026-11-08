"""Tests for machine-key JWT → access token minting."""

from __future__ import annotations

import json
from urllib.parse import parse_qs, unquote

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.zitadel_auth import load_machine_key, mint_access_token


def _rsa_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def test_load_machine_key_requires_fields() -> None:
    with pytest.raises(ValueError, match="keyId"):
        load_machine_key({"userId": "u", "key": "-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----"})


def test_load_machine_key_coerces_ids_to_str() -> None:
    pem = _rsa_pem()
    data = load_machine_key({"keyId": 11, "userId": 22, "key": pem})
    assert data["keyId"] == "11"
    assert data["userId"] == "22"


def test_mint_access_token_posts_jwt_bearer(monkeypatch: pytest.MonkeyPatch) -> None:
    pem = _rsa_pem()
    machine = {
        "type": "serviceaccount",
        "keyId": "kid-1",
        "key": pem,
        "userId": "user-1",
    }
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": "https://zitadel.example.com",
                    "token_endpoint": "https://zitadel.example.com/oauth/v2/token",
                },
            )
        captured["url"] = str(request.url)
        captured["body"] = request.read().decode()
        return httpx.Response(
            200, json={"access_token": "atok", "token_type": "Bearer", "expires_in": 300}
        )

    transport = httpx.MockTransport(handler)

    real_client = httpx.Client

    def client_factory(*args, **kwargs):
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "Client", client_factory)

    token = mint_access_token(
        base_url="https://zitadel.example.com",
        machine_key=json.dumps(machine),
    )
    assert token == "atok"
    assert captured["url"] == "https://zitadel.example.com/oauth/v2/token"
    form = parse_qs(captured["body"])
    assert form["grant_type"] == ["urn:ietf:params:oauth:grant-type:jwt-bearer"]
    assert "urn:zitadel:iam:org:project:id:zitadel:aud" in form["scope"][0]
    assertion = unquote(form["assertion"][0])
    # Decode without verify — we only assert claims; MockTransport already proved the POST.
    decoded = jwt.decode(
        assertion,
        options={"verify_signature": False},
        algorithms=["RS256"],
        audience="https://zitadel.example.com",
    )
    assert decoded["iss"] == "user-1"
    assert decoded["sub"] == "user-1"
    assert "https://zitadel.example.com:443" in decoded["aud"]
    header = jwt.get_unverified_header(assertion)
    assert header.get("kid") == "kid-1"


def test_mint_access_token_surfaces_token_error_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pem = _rsa_pem()
    machine = {"keyId": "k", "userId": "u", "key": pem}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": "https://zitadel.example.com",
                    "token_endpoint": "https://zitadel.example.com/oauth/v2/token",
                },
            )
        return httpx.Response(
            400, json={"error": "invalid_grant", "error_description": "audience"}
        )

    transport = httpx.MockTransport(handler)
    real_client = httpx.Client

    def client_factory(*args, **kwargs):
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "Client", client_factory)

    with pytest.raises(RuntimeError, match="invalid_grant") as exc:
        mint_access_token(base_url="https://zitadel.example.com", machine_key=machine)
    assert "aud=" in str(exc.value)
