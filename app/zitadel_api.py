"""Async Zitadel Management API helpers (machine-key JWT → short-lived bearer)."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.zitadel_auth import load_machine_key_from_env_or_file, mint_access_token

logger = logging.getLogger(__name__)

# Primary auth methods that mean the user is already set up (not "fresh").
_PRIMARY_AUTH_METHODS = frozenset(
    {
        "AUTHENTICATION_METHOD_TYPE_PASSWORD",
        "AUTHENTICATION_METHOD_TYPE_PASSKEY",
        "AUTHENTICATION_METHOD_TYPE_IDP",
        # Numeric enum fallbacks some gateways emit.
        "1",
        "2",
        "3",
    }
)


class ZitadelApiError(RuntimeError):
    pass


def mint_token_from_settings(
    *,
    base_url: str,
    machine_key_file: str = "",
    machine_key_json: str = "",
) -> str:
    machine_key = load_machine_key_from_env_or_file(
        json_env=machine_key_json,
        file_path=machine_key_file,
    )
    return mint_access_token(base_url=base_url, machine_key=machine_key)


async def list_auth_method_types(
    client: httpx.AsyncClient, user_id: str
) -> list[str]:
    resp = await client.get(f"/v2/users/{user_id}/authentication_methods")
    if resp.is_error:
        raise ZitadelApiError(
            f"list authentication methods failed (HTTP {resp.status_code}): {resp.text}"
        )
    raw = resp.json().get("authMethodTypes") or resp.json().get("auth_method_types") or []
    return [str(item) for item in raw]


def has_primary_auth_method(auth_method_types: list[str]) -> bool:
    return any(item in _PRIMARY_AUTH_METHODS for item in auth_method_types)


async def create_invite_code(client: httpx.AsyncClient, user_id: str) -> None:
    """Send an invite via the configured email (HTTP) provider."""
    resp = await client.post(
        f"/v2/users/{user_id}/invite_code",
        json={"sendCode": {}},
    )
    if resp.is_error:
        raise ZitadelApiError(
            f"create invite code failed (HTTP {resp.status_code}): {resp.text}"
        )


async def get_user_nickname(client: httpx.AsyncClient, user_id: str) -> str | None:
    resp = await client.get(f"/v2/users/{user_id}")
    if resp.is_error:
        raise ZitadelApiError(
            f"get user failed (HTTP {resp.status_code}): {resp.text}"
        )
    body = resp.json()
    user = body.get("user") or body
    human = user.get("human") or {}
    profile = human.get("profile") or {}
    nick = profile.get("nickName") or profile.get("nickname")
    if nick is None:
        return None
    text = str(nick).strip()
    return text or None


def api_client(base_url: str, access_token: str) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=base_url.rstrip("/"),
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        timeout=30.0,
    )


def parse_event_payload(raw: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    """
    Return (event_type, user_id, event_payload).

    Actions event envelope uses aggregateID as the user id for user.* events.
    event_payload may already be an object or (rarely) a JSON string.
    """
    event_type = str(raw.get("event_type") or raw.get("eventType") or "")
    user_id = str(
        raw.get("aggregateID")
        or raw.get("aggregateId")
        or raw.get("aggregate_id")
        or ""
    )
    payload = raw.get("event_payload") or raw.get("eventPayload") or {}
    if isinstance(payload, str):
        import json

        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            payload = {}
    if not isinstance(payload, dict):
        payload = {}
    return event_type, user_id, payload
