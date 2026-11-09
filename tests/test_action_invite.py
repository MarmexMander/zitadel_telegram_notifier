"""Invite-on-nickname Action handler guards."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from app.action_invite import handle_profile_event
from app.db import AutoInviteStore


def _event(
    *,
    event_type: str = "user.human.profile.changed",
    user_id: str = "user-1",
    nick: str | None = "alice_tg",
) -> dict[str, Any]:
    payload: dict[str, Any] = {"firstName": "Alice", "lastName": "T"}
    if nick is not None:
        payload["nickName"] = nick
    return {
        "aggregateID": user_id,
        "event_type": event_type,
        "event_payload": payload,
    }


@pytest.mark.asyncio
async def test_skips_non_handled_event(session) -> None:
    store = AutoInviteStore(session)
    result = await handle_profile_event(
        body=_event(event_type="user.human.email.changed"),
        store=store,
        base_url="https://zitadel.example.com",
        machine_key_file="/tmp/key.json",
    )
    assert result.status == "ignored"


@pytest.mark.asyncio
async def test_skips_missing_nickname(session) -> None:
    store = AutoInviteStore(session)
    result = await handle_profile_event(
        body=_event(nick=None),
        store=store,
        base_url="https://zitadel.example.com",
        machine_key_file="/tmp/key.json",
    )
    assert result.status == "skipped"
    assert "no nickName" in result.detail


@pytest.mark.asyncio
async def test_skips_invalid_handle(session) -> None:
    store = AutoInviteStore(session)
    result = await handle_profile_event(
        body=_event(nick="ab"),
        store=store,
        base_url="https://zitadel.example.com",
        machine_key_file="/tmp/key.json",
    )
    assert result.status == "skipped"
    assert "invalid" in result.detail


@pytest.mark.asyncio
async def test_skips_when_already_sent(session) -> None:
    store = AutoInviteStore(session)
    await store.record_sent(user_id="user-1", handle="alice_tg")
    result = await handle_profile_event(
        body=_event(),
        store=store,
        base_url="https://zitadel.example.com",
        machine_key_file="/tmp/key.json",
    )
    assert result.status == "skipped"
    assert "already invited" in result.detail


@pytest.mark.asyncio
async def test_skips_when_user_has_password(session) -> None:
    store = AutoInviteStore(session)
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    with (
        patch(
            "app.action_invite.mint_token_from_settings",
            return_value="tok",
        ),
        patch("app.action_invite.api_client", return_value=mock_client),
        patch(
            "app.action_invite.get_user_nickname",
            new=AsyncMock(return_value="alice_tg"),
        ),
        patch(
            "app.action_invite.list_auth_method_types",
            new=AsyncMock(
                return_value=["AUTHENTICATION_METHOD_TYPE_PASSWORD"]
            ),
        ),
        patch(
            "app.action_invite.create_invite_code",
            new=AsyncMock(),
        ) as create_invite,
    ):
        result = await handle_profile_event(
            body=_event(),
            store=store,
            base_url="https://zitadel.example.com",
            machine_key_file="/tmp/key.json",
        )
    assert result.status == "skipped"
    assert "not fresh" in result.detail
    create_invite.assert_not_called()


@pytest.mark.asyncio
async def test_sends_invite_for_fresh_user(session) -> None:
    store = AutoInviteStore(session)
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    with (
        patch(
            "app.action_invite.mint_token_from_settings",
            return_value="tok",
        ),
        patch("app.action_invite.api_client", return_value=mock_client),
        patch(
            "app.action_invite.get_user_nickname",
            new=AsyncMock(return_value="@Alice_TG"),
        ),
        patch(
            "app.action_invite.list_auth_method_types",
            new=AsyncMock(return_value=[]),
        ),
        patch(
            "app.action_invite.create_invite_code",
            new=AsyncMock(),
        ) as create_invite,
    ):
        result = await handle_profile_event(
            body=_event(nick="@Alice_TG"),
            store=store,
            base_url="https://zitadel.example.com",
            machine_key_file="/tmp/key.json",
        )
        await session.commit()

    assert result.status == "sent"
    create_invite.assert_awaited_once()
    assert await store.already_sent(user_id="user-1", handle="alice_tg")
