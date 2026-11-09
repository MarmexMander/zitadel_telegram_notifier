"""Idempotent ensure-invite-action (mocked Actions API)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from app.crypto import Seal
from app.db import ActionKeyStore, create_engine, create_session_factory, init_db
from cli.__main__ import CliSettings, cmd_ensure_invite_action


def _settings(**kwargs: Any) -> CliSettings:
    base = {
        "MASTER_KEY": "test-master-key",
        "DATABASE_URL": "sqlite+aiosqlite:///:memory:",
        "ZITADEL_BASE_URL": "https://zitadel.example.com",
        "ZITADEL_ACCESS_TOKEN": "test-token",
        "ZITADEL_ACTION_ENDPOINT": "http://172.30.50.2:8080/zitadel/action/invite",
        "ZITADEL_ACTION_NAME": "telegram-invite-on-nickname",
    }
    base.update(kwargs)
    return CliSettings(**base)  # type: ignore[arg-type]


def _resp(payload: dict, *, status: int = 200) -> SimpleNamespace:
    return SimpleNamespace(
        is_error=status >= 400,
        status_code=status,
        text="",
        raise_for_status=lambda: None,
        json=lambda: payload,
    )


@pytest.mark.asyncio
async def test_ensure_creates_target_and_executions(tmp_path) -> None:
    url = f"sqlite+aiosqlite:///{tmp_path / 'action.db'}"
    settings = _settings(DATABASE_URL=url)

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    puts: list[dict] = []

    async def post(path, json=None):  # noqa: A002
        if path.endswith("/targets/search"):
            return _resp({"targets": []})
        if path.endswith("/actions/targets"):
            return _resp({"id": "tgt-1", "signingKey": "action-secret"})
        raise AssertionError(f"unexpected POST {path}")

    async def put(path, json=None):  # noqa: A002
        puts.append(json or {})
        return _resp({"setDate": "2026-01-01T00:00:00Z"})

    mock_client.post = post
    mock_client.put = put

    with patch("cli.__main__._client", return_value=mock_client):
        rc = await cmd_ensure_invite_action(settings)
    assert rc == 0
    assert len(puts) == 2
    events = {p["condition"]["event"]["event"] for p in puts}
    assert events == {"user.human.profile.changed", "user.human.added"}

    engine = create_engine(url)
    factory = create_session_factory(engine)
    seal = Seal("test-master-key")
    async with factory() as session:
        store = ActionKeyStore(session, seal)
        assert await store.has_active_key()
        assert await store.get_target_id() == "tgt-1"
        keys = await store.list_verification_keys()
        assert keys == ["action-secret"]
    await engine.dispose()


@pytest.mark.asyncio
async def test_ensure_reuses_existing_target(tmp_path) -> None:
    url = f"sqlite+aiosqlite:///{tmp_path / 'reuse.db'}"
    settings = _settings(DATABASE_URL=url)

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    async def post(path, json=None):  # noqa: A002
        if path.endswith("/targets/search"):
            return _resp(
                {
                    "targets": [
                        {
                            "id": "tgt-existing",
                            "name": "telegram-invite-on-nickname",
                            "endpoint": (
                                "http://172.30.50.2:8080/zitadel/action/invite"
                            ),
                            "signingKey": "existing-secret",
                        }
                    ]
                }
            )
        raise AssertionError(f"unexpected POST {path}")

    async def put(path, json=None):  # noqa: A002
        return _resp({"setDate": "2026-01-01T00:00:00Z"})

    mock_client.post = post
    mock_client.put = put

    with patch("cli.__main__._client", return_value=mock_client):
        rc = await cmd_ensure_invite_action(settings)
    assert rc == 0

    engine = create_engine(url)
    factory = create_session_factory(engine)
    seal = Seal("test-master-key")
    async with factory() as session:
        store = ActionKeyStore(session, seal)
        assert await store.get_target_id() == "tgt-existing"
        assert await store.list_verification_keys() == ["existing-secret"]
    await engine.dispose()
