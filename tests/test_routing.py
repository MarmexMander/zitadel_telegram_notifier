"""Ingest routing by the email field (<handle>@telegram)."""

from __future__ import annotations

from typing import Any

import pytest

from app.service import NotifierService


class FakeTelegram:
    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []

    async def send_text(self, chat_id: int, text: str, **kwargs: Any) -> None:
        self.sent.append({"chat_id": chat_id, "text": text, **kwargs})

    async def send_notification(self, chat_id: int, **kwargs: Any) -> None:
        self.sent.append({"chat_id": chat_id, "notification": kwargs})

    async def leave_chat(self, chat_id: int) -> None:
        pass

    async def notify_admins(self, admin_chat_ids: list[int], text: str) -> None:
        self.sent.append({"admins": admin_chat_ids, "text": text})


def _payload(email: str | None, nick: str | None = None) -> dict[str, Any]:
    context: dict[str, Any] = {"eventType": "user.human.initialization.code.added"}
    if email is not None:
        context["recipientEmailAddress"] = email
    args: dict[str, Any] = {"preferredLoginName": "alice@org"}
    if nick is not None:
        args["nickName"] = nick
    return {
        "contextInfo": context,
        "templateData": {"subject": "Hi", "text": "Body", "buttonText": "Go"},
        "args": args,
    }


@pytest.mark.asyncio
async def test_telegram_address_is_queued(session, seal, settings) -> None:
    service = NotifierService(session, seal, FakeTelegram(), settings)  # type: ignore[arg-type]
    await service.ingest_zitadel_payload(_payload("Alice_TG@telegram"))
    await session.commit()
    assert len(await service.outbox.pending_for_handle("alice_tg")) == 1


@pytest.mark.asyncio
async def test_bare_handle_from_router_is_queued(session, seal, settings) -> None:
    service = NotifierService(session, seal, FakeTelegram(), settings)  # type: ignore[arg-type]
    await service.ingest_zitadel_payload(_payload("alice_tg"))
    await session.commit()
    assert len(await service.outbox.pending_for_handle("alice_tg")) == 1


@pytest.mark.asyncio
async def test_real_email_is_ignored_even_with_nickname(session, seal, settings) -> None:
    tg = FakeTelegram()
    service = NotifierService(session, seal, tg, settings)  # type: ignore[arg-type]
    await service.ingest_zitadel_payload(_payload("alice@example.com", nick="alice_tg"))
    await session.commit()
    assert await service.outbox.pending_for_handle("alice_tg") == []
    assert tg.sent == []  # no admin alert for "not ours"


@pytest.mark.asyncio
async def test_invalid_handle_alerts_admins(session, seal, settings) -> None:
    tg = FakeTelegram()
    service = NotifierService(session, seal, tg, settings)  # type: ignore[arg-type]
    await service.ingest_zitadel_payload(_payload("ab@telegram"))
    assert tg.sent and "invalid recipient" in tg.sent[0]["text"]
