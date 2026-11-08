"""Idempotent register / recover paths (mocked Admin API)."""

from __future__ import annotations

import json
from typing import Any
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from app.crypto import Seal
from app.db import KeyStore, create_engine, create_session_factory, init_db
from cli.__main__ import CliSettings, cmd_register


def _settings(**kwargs: Any) -> CliSettings:
    base = {
        "MASTER_KEY": "test-master-key",
        "DATABASE_URL": "sqlite+aiosqlite:///:memory:",
        "ZITADEL_BASE_URL": "https://zitadel.example.com",
        "ZITADEL_ACCESS_TOKEN": "test-token",
        "ZITADEL_PROVIDER_ENDPOINT": "http://172.30.50.2:8080/zitadel/hook",
    }
    base.update(kwargs)
    return CliSettings(**base)  # type: ignore[arg-type]


def _resp(payload: dict) -> SimpleNamespace:
    return SimpleNamespace(
        is_error=False,
        text="",
        raise_for_status=lambda: None,
        json=lambda: payload,
    )


@pytest.mark.asyncio
async def test_register_noop_when_local_key_exists(tmp_path) -> None:
    url = f"sqlite+aiosqlite:///{tmp_path / 'reg.db'}"
    engine = create_engine(url)
    await init_db(engine)
    factory = create_session_factory(engine)
    seal = Seal("test-master-key")
    async with factory() as session:
        store = KeyStore(session, seal)
        await store.upsert_provider_meta(
            provider_id="prov-1",
            endpoint="http://172.30.50.2:8080/zitadel/hook",
            description="Telegram notifier",
        )
        await store.store_active(
            provider_id="prov-1",
            signing_key="signing-secret",
            fingerprint="abcd",
        )
        await session.commit()
    await engine.dispose()

    settings = _settings(DATABASE_URL=url)
    with patch("cli.__main__._client") as client_factory:
        rc = await cmd_register(settings)
    assert rc == 0
    client_factory.assert_not_called()


@pytest.mark.asyncio
async def test_register_creates_when_missing(tmp_path) -> None:
    url = f"sqlite+aiosqlite:///{tmp_path / 'create.db'}"
    settings = _settings(DATABASE_URL=url)

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    async def post(path, json=None):  # noqa: A002
        if path.endswith("/_search"):
            return _resp({"result": []})
        if path.endswith("/email/http"):
            return _resp({"id": "new-prov", "signingKey": "new-secret"})
        if path.endswith("/_activate"):
            return _resp({})
        raise AssertionError(path)

    mock_client.post = post

    with patch("cli.__main__._client", return_value=mock_client):
        rc = await cmd_register(settings)
    assert rc == 0

    engine = create_engine(url)
    factory = create_session_factory(engine)
    async with factory() as session:
        store = KeyStore(session, Seal("test-master-key"))
        assert await store.has_active_key()
        assert await store.get_provider_id() == "new-prov"
    await engine.dispose()
