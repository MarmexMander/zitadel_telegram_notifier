"""Recipient addressing: the "email" field carries the messenger handle.

Scheme (this notifier): ``<handle>@telegram`` — a domain with no dot, so it can
never collide with a real mailbox. Other channels will use their own dotless
suffix (``@signal``, …); anything with a dotted domain is a normal email.

Future split:

- *router* container: reads the recipient, picks the suffix owner, forwards the
  original payload to that notifier (and may strip the suffix itself).
- *notifier* container (this one): accepts either ``handle@telegram`` or a bare
  ``handle`` (router already stripped it). Any other ``@domain`` is not ours.

This module is the only place that knows the scheme; callers deal in
``Recipient`` so a second channel only needs its own ``parse_*`` here.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.handles import InvalidHandleError, normalize_handle

CHANNEL_TELEGRAM = "telegram"
DEFAULT_SUFFIX = "telegram"


class NotForChannelError(ValueError):
    """Address belongs to another channel (or a real mailbox); not an error per se."""


@dataclass(frozen=True)
class Recipient:
    channel: str
    handle: str

    @property
    def address(self) -> str:
        return f"{self.handle}@{self.channel}"


def parse_recipient(raw: str | None, *, suffix: str = DEFAULT_SUFFIX) -> Recipient:
    """
    Resolve a Telegram recipient from an "email" value.

    Accepts ``alice_tg@telegram`` (any case) or a bare/``@``-prefixed handle that
    a router already stripped. Raises:

    - ``NotForChannelError`` — different ``@domain`` (route elsewhere / real email)
    - ``InvalidHandleError`` — ours, but not a valid Telegram username
    """
    if raw is None or not str(raw).strip():
        raise InvalidHandleError("recipient is empty")
    value = str(raw).strip()
    suffix = suffix.strip().casefold()

    local, sep, domain = value.rpartition("@")
    if sep and local:
        # "alice@telegram" form. A leading-@ bare handle ("@alice") has empty local.
        if domain.strip().casefold() != suffix:
            raise NotForChannelError(f"recipient domain {domain!r} is not @{suffix}")
        handle_part = local
    else:
        handle_part = value  # bare handle, optionally "@alice"

    return Recipient(
        channel=CHANNEL_TELEGRAM,
        handle=normalize_handle(handle_part),
    )


def recipient_from_payload(
    payload: dict,
    *,
    suffix: str = DEFAULT_SUFFIX,
) -> Recipient:
    """
    Pick the recipient out of a Zitadel HTTP email-provider payload.

    Reads ``contextInfo.recipientEmailAddress`` only; Nickname is never consulted.
    """
    context = payload.get("contextInfo") or {}
    raw_email = context.get("recipientEmailAddress")
    if not isinstance(raw_email, str) or not raw_email.strip():
        raise InvalidHandleError("payload has no recipientEmailAddress")
    return parse_recipient(raw_email, suffix=suffix)
