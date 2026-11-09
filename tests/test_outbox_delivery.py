"""Invite queued before /start is delivered when the matching user starts the bot."""

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


def _invite_payload(*, nick: str = "alice_tg", login: str = "alice@org") -> dict[str, Any]:
    return {
        "contextInfo": {
            "eventType": "user.human.initialization.code.added",
            "recipientEmailAddress": f"{nick}@telegram",
        },
        "templateData": {
            "subject": "Initialize User",
            "greeting": "Hello Alice,",
            "text": "Finish initialization.",
            "url": "https://zitadel.example.com/ui/login/user/init?code=ABC",
            "buttonText": "Finish initialization",
        },
        "args": {
            "nickName": nick,
            "preferredLoginName": login,
            "userName": "alice",
        },
    }


@pytest.mark.asyncio
async def test_outbox_delivery_after_start(session, seal, settings) -> None:
    tg = FakeTelegram()
    service = NotifierService(session, seal, tg, settings)  # type: ignore[arg-type]

    await service.ingest_zitadel_payload(_invite_payload())
    await session.commit()

    # Nothing delivered yet — user has not /start'd.
    assert tg.sent == []
    pending = await service.outbox.pending_for_handle("alice_tg")
    assert len(pending) == 1

    await service.handle_telegram_update(
        {
            "message": {
                "chat": {"id": 4242, "type": "private"},
                "from": {"id": 4242, "username": "Alice_TG"},
                "text": "/start",
            }
        }
    )
    await session.commit()

    assert len(tg.sent) == 1
    note = tg.sent[0]["notification"]
    assert note["subject"] == "Initialize User"
    assert note["url"].startswith("https://zitadel.example.com/")
    assert note["button_text"] == "Finish initialization"

    binding = await service.bindings.get_by_login("alice@org")
    assert binding is not None
    assert binding.telegram_user_id == 4242

    # Outbox cleared after delivery.
    assert await service.outbox.pending_for_handle("alice_tg") == []


@pytest.mark.asyncio
async def test_pinned_user_gets_later_events_immediately(session, seal, settings) -> None:
    tg = FakeTelegram()
    service = NotifierService(session, seal, tg, settings)  # type: ignore[arg-type]

    await service.ingest_zitadel_payload(_invite_payload())
    await service.handle_telegram_update(
        {
            "message": {
                "chat": {"id": 4242, "type": "private"},
                "from": {"id": 4242, "username": "alice_tg"},
                "text": "/start",
            }
        }
    )
    tg.sent.clear()

    await service.ingest_zitadel_payload(
        {
            "contextInfo": {
                "eventType": "user.human.password.code.added",
                "recipientEmailAddress": "alice_tg@telegram",
            },
            "templateData": {
                "subject": "Reset password",
                "greeting": "Hello,",
                "text": "Reset your password.",
                "url": "https://zitadel.example.com/reset",
                "buttonText": "Reset",
            },
            "args": {
                "preferredLoginName": "alice@org",
            },
        }
    )

    assert len(tg.sent) == 1
    assert tg.sent[0]["notification"]["subject"] == "Reset password"


@pytest.mark.asyncio
async def test_unlink_clears_pin(session, seal, settings) -> None:
    tg = FakeTelegram()
    service = NotifierService(session, seal, tg, settings)  # type: ignore[arg-type]

    await service.ingest_zitadel_payload(_invite_payload())
    await service.handle_telegram_update(
        {
            "message": {
                "chat": {"id": 4242, "type": "private"},
                "from": {"id": 4242, "username": "alice_tg"},
                "text": "/start",
            }
        }
    )
    assert await service.bindings.get_by_login("alice@org") is not None

    assert await service.bindings.unlink("alice@org") is True
    assert await service.bindings.get_by_login("alice@org") is None
    assert await service.bindings.unlink("alice@org") is False
