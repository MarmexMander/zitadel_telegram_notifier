"""Mint short-lived Zitadel API access tokens from a machine-user private key JWT."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import httpx
import jwt


def load_machine_key(raw: str | dict[str, Any]) -> dict[str, Any]:
    """Parse Zitadel service-account key JSON (string or already-decoded dict)."""
    if isinstance(raw, dict):
        data = raw
    else:
        text = raw.strip()
        if not text:
            raise ValueError("machine key JSON is empty")
        data = json.loads(text)
    for field in ("keyId", "key", "userId"):
        if field not in data or data[field] in (None, ""):
            raise ValueError(f"machine key JSON missing {field!r}")
    # Zitadel may encode ids as numbers in some exports; JWT claims must be strings.
    data["keyId"] = str(data["keyId"])
    data["userId"] = str(data["userId"])
    if not isinstance(data["key"], str) or "BEGIN" not in data["key"]:
        raise ValueError("machine key JSON 'key' must be a PEM private key string")
    return data


def load_machine_key_from_env_or_file(
    *,
    json_env: str = "",
    file_path: str = "",
) -> dict[str, Any]:
    if file_path.strip():
        path = Path(file_path.strip())
        return load_machine_key(path.read_text(encoding="utf-8"))
    if json_env.strip():
        return load_machine_key(json_env)
    raise ValueError("set ZITADEL_MACHINE_KEY_FILE or ZITADEL_MACHINE_KEY_JSON")


def _audiences_for_issuer(issuer: str) -> list[str]:
    """JWT aud values ZITADEL accepts for the JWT profile grant."""
    issuer = issuer.rstrip("/")
    audiences = [issuer]
    # Some deployments match audience with an explicit :443.
    if issuer.startswith("https://") and not issuer.endswith(":443"):
        audiences.append(f"{issuer}:443")
    return audiences


def resolve_token_endpoint_and_audiences(
    *,
    base_url: str,
    client: httpx.Client,
) -> tuple[str, list[str]]:
    """
    Prefer OIDC discovery so aud matches the live issuer (not EXTERNALDOMAIN env drift).
    Falls back to base_url when discovery is unavailable.
    """
    base = base_url.rstrip("/")
    token_url = f"{base}/oauth/v2/token"
    issuer = base
    try:
        conf_resp = client.get(f"{base}/.well-known/openid-configuration")
        if conf_resp.is_success:
            conf = conf_resp.json()
            if conf.get("issuer"):
                issuer = str(conf["issuer"]).rstrip("/")
            if conf.get("token_endpoint"):
                token_url = str(conf["token_endpoint"])
    except Exception:
        pass
    return token_url, _audiences_for_issuer(issuer)


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
    JWT aud is the OIDC issuer (custom domain), never the token URL path.
    """
    key = load_machine_key(machine_key)
    base = base_url.rstrip("/")
    now = int(time.time())
    with httpx.Client(timeout=timeout) as client:
        token_url, audiences = resolve_token_endpoint_and_audiences(
            base_url=base, client=client
        )
        assertion = jwt.encode(
            {
                "iss": key["userId"],
                "sub": key["userId"],
                "aud": audiences,
                "iat": now,
                "exp": now + lifetime_seconds,
            },
            key["key"],
            algorithm="RS256",
            headers={"kid": key["keyId"]},
        )
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
            detail: Any = resp.text
            try:
                detail = resp.json()
            except Exception:
                pass
            raise RuntimeError(
                "Zitadel token endpoint rejected JWT profile grant "
                f"(HTTP {resp.status_code}): {detail}; "
                f"aud={audiences!r} userId={key['userId']!r} keyId={key['keyId']!r} "
                f"base_url={base!r} token_url={token_url!r}"
            )
        body = resp.json()
    token = body.get("access_token")
    if not token:
        raise ValueError("token response missing access_token")
    return token
