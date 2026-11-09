"""Recipient addressing: handle@telegram in the email field."""

from __future__ import annotations

import pytest

from app.handles import InvalidHandleError
from app.recipient import (
    NotForChannelError,
    parse_recipient,
    recipient_from_payload,
)


@pytest.mark.parametrize(
    "raw",
    [
        "alice_tg@telegram",
        "Alice_TG@Telegram",
        "  alice_tg@telegram  ",
        "alice_tg",  # router already stripped the suffix
        "@alice_tg",
    ],
)
def test_parse_accepts_ours(raw: str) -> None:
    recipient = parse_recipient(raw)
    assert recipient.handle == "alice_tg"
    assert recipient.channel == "telegram"
    assert recipient.address == "alice_tg@telegram"


@pytest.mark.parametrize(
    "raw", ["alice@example.com", "alice_tg@signal", "alice_tg@telegram.org"]
)
def test_parse_rejects_other_channels(raw: str) -> None:
    with pytest.raises(NotForChannelError):
        parse_recipient(raw)


@pytest.mark.parametrize("raw", [None, "", "   ", "ab@telegram", "bad name@telegram"])
def test_parse_rejects_invalid_handle(raw) -> None:
    with pytest.raises(InvalidHandleError):
        parse_recipient(raw)


def test_custom_suffix() -> None:
    assert parse_recipient("alice_tg@tg", suffix="tg").handle == "alice_tg"
    with pytest.raises(NotForChannelError):
        parse_recipient("alice_tg@telegram", suffix="tg")


def _payload(email: str | None, nick: str | None = None) -> dict:
    context = {"eventType": "user.human.initialization.code.added"}
    if email is not None:
        context["recipientEmailAddress"] = email
    args = {"nickName": nick} if nick is not None else {}
    return {"contextInfo": context, "args": args}


def test_from_payload_uses_email() -> None:
    assert recipient_from_payload(_payload("alice_tg@telegram")).handle == "alice_tg"


def test_from_payload_ignores_nickname() -> None:
    with pytest.raises(NotForChannelError):
        recipient_from_payload(_payload("alice@example.com", nick="alice_tg"))


def test_from_payload_missing_email() -> None:
    with pytest.raises(InvalidHandleError):
        recipient_from_payload(_payload(None))
