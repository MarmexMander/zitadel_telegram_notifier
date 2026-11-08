"""Unmatched /start returns the wait-for-admin message with no contact points."""

from __future__ import annotations

from typing import Any

import pytest

from app.handles import UNMATCHED_START_MESSAGE
from app.service import NotifierService


class FakeTelegram:
    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []
        self.left: list[int] = []

    async def send_text(self, chat_id: int, text: str, **kwargs: Any) -> None:
        self.sent.append({"chat_id": chat_id, "text": text, **kwargs})

    async def send_notification(self, chat_id: int, **kwargs: Any) -> None:
        self.sent.append({"chat_id": chat_id, "notification": kwargs})

    async def leave_chat(self, chat_id: int) -> None:
        self.left.append(chat_id)

    async def notify_admins(self, admin_chat_ids: list[int], text: str) -> None:
        self.sent.append({"admins": admin_chat_ids, "text": text})


@pytest.mark.asyncio
async def test_unmatched_start_message(session, seal, settings) -> None:
    tg = FakeTelegram()
    service = NotifierService(session, seal, tg, settings)  # type: ignore[arg-type]

    await service.handle_telegram_update(
        {
            "message": {
                "chat": {"id": 42, "type": "private"},
                "from": {"id": 42, "username": "nobody_here"},
                "text": "/start",
            }
        }
    )

    assert len(tg.sent) == 1
    assert tg.sent[0]["chat_id"] == 42
    assert tg.sent[0]["text"] == UNMATCHED_START_MESSAGE
    # No contact points / links in the unmatched copy.
    assert "@" not in tg.sent[0]["text"]
    assert "http" not in tg.sent[0]["text"].lower()
    assert "t.me" not in tg.sent[0]["text"].lower()


@pytest.mark.asyncio
async def test_start_without_username(session, seal, settings) -> None:
    tg = FakeTelegram()
    service = NotifierService(session, seal, tg, settings)  # type: ignore[arg-type]

    await service.handle_telegram_update(
        {
            "message": {
                "chat": {"id": 7, "type": "private"},
                "from": {"id": 7},
                "text": "/start",
            }
        }
    )

    assert tg.sent[0]["text"] == UNMATCHED_START_MESSAGE


@pytest.mark.asyncio
async def test_leaves_group_chats(session, seal, settings) -> None:
    tg = FakeTelegram()
    service = NotifierService(session, seal, tg, settings)  # type: ignore[arg-type]

    await service.handle_telegram_update(
        {
            "message": {
                "chat": {"id": -1001, "type": "group"},
                "from": {"id": 99, "username": "alice_tg"},
                "text": "/start",
            }
        }
    )

    assert tg.left == [-1001]
    assert tg.sent == []
