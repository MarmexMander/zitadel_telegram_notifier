"""Locale extraction, normalization, catalogs, and unmatched /start language."""

from __future__ import annotations

from typing import Any

import pytest

from app.i18n import (
    DEFAULT_LOCALE,
    extract_locale,
    extract_locale_tag,
    normalize_locale,
    resolve_locale,
    t,
)
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


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("en", "en"),
        ("en-US", "en"),
        ("EN_GB", "en"),
        ("uk", "uk"),
        ("uk-UA", "uk"),
        ("uk_ua", "uk"),
        ("de", DEFAULT_LOCALE),
        ("", DEFAULT_LOCALE),
        (None, DEFAULT_LOCALE),
        ("  ", DEFAULT_LOCALE),
    ],
)
def test_normalize_locale(raw: str | None, expected: str) -> None:
    assert normalize_locale(raw) == expected


def test_extract_from_args_preferred_language() -> None:
    payload = {"args": {"preferredLanguage": "uk-UA", "nickName": "alice"}}
    assert extract_locale_tag(payload) == "uk-UA"
    assert extract_locale(payload) == "uk"


def test_extract_from_args_pascal_case() -> None:
    payload = {"args": {"PreferredLanguage": "en-US"}}
    assert extract_locale(payload) == "en"


def test_extract_from_nested_profile() -> None:
    payload = {"args": {"profile": {"preferredLanguage": "uk"}}}
    assert extract_locale(payload) == "uk"


def test_extract_missing_returns_none() -> None:
    # Typical Zitadel v4.16 webhook: PreferredLanguage used for templateData only.
    payload = {
        "args": {"nickName": "alice", "preferredLoginName": "alice@org"},
        "templateData": {"subject": "Initialize User", "text": "..."},
    }
    assert extract_locale_tag(payload) is None
    assert extract_locale(payload) is None


def test_resolve_prefers_payload_over_stored() -> None:
    assert (
        resolve_locale(
            payload={"args": {"preferredLanguage": "uk"}},
            stored="en",
            telegram_language_code="de",
        )
        == "uk"
    )


def test_resolve_falls_back_to_stored() -> None:
    assert resolve_locale(payload={"args": {}}, stored="uk") == "uk"


def test_resolve_telegram_last_resort() -> None:
    assert resolve_locale(telegram_language_code="uk-UA") == "uk"
    assert resolve_locale() == DEFAULT_LOCALE


def test_catalogs_en_and_uk() -> None:
    en = t("unmatched_start", "en")
    uk = t("unmatched_start", "uk")
    assert "not in the system" in en
    assert "немає в системі" in uk
    assert t("open_link", "uk") == "Відкрити"


@pytest.mark.asyncio
async def test_unmatched_start_defaults_to_en(session, seal, settings) -> None:
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

    assert tg.sent[0]["text"] == t("unmatched_start", "en")


@pytest.mark.asyncio
async def test_unmatched_start_uses_telegram_language_as_last_resort(
    session, seal, settings
) -> None:
    tg = FakeTelegram()
    service = NotifierService(session, seal, tg, settings)  # type: ignore[arg-type]

    await service.handle_telegram_update(
        {
            "message": {
                "chat": {"id": 42, "type": "private"},
                "from": {
                    "id": 42,
                    "username": "nobody_here",
                    "language_code": "uk",
                },
                "text": "/start",
            }
        }
    )

    assert tg.sent[0]["text"] == t("unmatched_start", "uk")


@pytest.mark.asyncio
async def test_binding_locale_from_payload_and_refresh(session, seal, settings) -> None:
    tg = FakeTelegram()
    service = NotifierService(session, seal, tg, settings)  # type: ignore[arg-type]

    invite = {
        "contextInfo": {
            "eventType": "user.human.initialization.code.added",
            "recipientEmailAddress": "alice_tg@telegram",
        },
        "templateData": {
            "subject": "Initialize User",
            "greeting": "Привіт,",
            "text": "Завершіть ініціалізацію.",
            "url": "https://zitadel.example.com/init",
            "buttonText": "Завершити",
        },
        "args": {
            "preferredLoginName": "alice@org",
            "preferredLanguage": "uk-UA",
        },
    }
    await service.ingest_zitadel_payload(invite)
    await session.commit()

    pending = await service.outbox.pending_for_handle("alice_tg")
    assert pending[0].locale == "uk"

    await service.handle_telegram_update(
        {
            "message": {
                "chat": {"id": 4242, "type": "private"},
                "from": {"id": 4242, "username": "alice_tg", "language_code": "en"},
                "text": "/start",
            }
        }
    )
    await session.commit()

    binding = await service.bindings.get_by_login("alice@org")
    assert binding is not None
    assert binding.locale == "uk"
    # Zitadel buttonText kept; open_link_label would only apply without buttonText.
    assert tg.sent[0]["notification"]["button_text"] == "Завершити"
    assert tg.sent[0]["notification"]["open_link_label"] == t("open_link", "uk")

    tg.sent.clear()
    await service.ingest_zitadel_payload(
        {
            "contextInfo": {
                "eventType": "user.human.password.code.added",
                "recipientEmailAddress": "alice_tg@telegram",
            },
            "templateData": {
                "subject": "Reset password",
                "text": "Reset.",
                "url": "https://zitadel.example.com/reset",
                "buttonText": "Reset",
            },
            "args": {
                "preferredLoginName": "alice@org",
                "preferredLanguage": "en-US",
            },
        }
    )
    binding = await service.bindings.get_by_login("alice@org")
    assert binding is not None
    assert binding.locale == "en"
    assert tg.sent[0]["notification"]["open_link_label"] == t("open_link", "en")
