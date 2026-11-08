"""Mint short-lived Zitadel API access tokens from a machine-user private key JWT."""

from __future__ import annotations

import json
import time
from typing import Any

import httpx
import jwt


def load_machine_key(raw: str | dict[str, Any]) -> dict[str, Any]:
    """Parse Zitadel service-account key JSON (string or already-decoded dict)."""
    if isinstance(raw, dict):
        data = raw
    else:
        data = json.loads(raw)
    for field in ("keyId", "key", "userId"):
        if not data.get(field):
            raise ValueError(f"machine key JSON missing {field!r}")
    return data


def mint_access_token(
    *,
    base_url: str,
    machine_key: str | dict[str, Any],
    lifetime_seconds: int = 300,
    timeout: float = 30.0,
) -> str:
    """
    Exchange a private-key JWT for a short-lived access token usable on Zitadel APIs.

    Requires scope urn:zitadel:iam:org:project:id:zitadel:aud.
    """
    key = load_machine_key(machine_key)
    # aud must be the issuer / custom domain, not the token URL (ZITADEL JWT Profile).
    base = base_url.rstrip("/")
    token_url = f"{base}/oauth/v2/token"
    now = int(time.time())
    assertion = jwt.encode(
        {
            "iss": key["userId"],
            "sub": key["userId"],
            "aud": base,
            "iat": now,
            "exp": now + lifetime_seconds,
        },
        key["key"],
        algorithm="RS256",
        headers={"kid": key["keyId"]},
    )
    with httpx.Client(timeout=timeout) as client:
        resp = client.post(
            token_url,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "scope": "openid urn:zitadel:iam:org:project:id:zitadel:aud",
                "assertion": assertion,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if resp.is_error:
            detail = resp.text
            try:
                detail = resp.json()
            except Exception:
                pass
            raise httpx.HTTPStatusError(
                f"token endpoint {resp.status_code}: {detail}",
                request=resp.request,
                response=resp,
            )
        body = resp.json()
    token = body.get("access_token")
    if not token:
        raise ValueError("token response missing access_token")
    return token
