"""Auto-send invite when a fresh user's Nickname becomes a Telegram handle."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.db import AutoInviteStore
from app.handles import InvalidHandleError, normalize_handle
from app.zitadel_api import (
    ZitadelApiError,
    api_client,
    create_invite_code,
    get_user_nickname,
    has_primary_auth_method,
    list_auth_method_types,
    mint_token_from_settings,
    parse_event_payload,
)

logger = logging.getLogger(__name__)

# Events that may carry a new/updated nickName for a human user.
HANDLED_EVENTS = frozenset(
    {
        "user.human.profile.changed",
        "user.human.added",
    }
)


class InviteActionResult:
    def __init__(self, status: str, detail: str = "") -> None:
        self.status = status
        self.detail = detail


async def handle_profile_event(
    *,
    body: dict[str, Any],
    store: AutoInviteStore,
    base_url: str,
    machine_key_file: str,
    machine_key_json: str = "",
) -> InviteActionResult:
    """
    Decide whether to CreateInviteCode for this Actions event.

    Always returns a result; callers map to HTTP 2xx so Zitadel does not retry
    forever on intentional skips (async/webhook targets still prefer 2xx).
    """
    event_type, user_id, payload = parse_event_payload(body)
    if event_type not in HANDLED_EVENTS:
        return InviteActionResult("ignored", f"event={event_type or 'unknown'}")
    if not user_id:
        return InviteActionResult("ignored", "missing aggregateID")

    nick_raw = payload.get("nickName") or payload.get("nickname")
    if nick_raw is None or str(nick_raw).strip() == "":
        # profile.changed for other fields — nothing to do.
        return InviteActionResult("skipped", "no nickName in event")

    try:
        handle = normalize_handle(str(nick_raw))
    except InvalidHandleError as exc:
        logger.info(
            "invite-action skip user=%s: invalid nickName (%s)", user_id, exc
        )
        return InviteActionResult("skipped", "invalid telegram handle")

    if await store.already_sent(user_id=user_id, handle=handle):
        return InviteActionResult("skipped", "already invited for this handle")

    if not base_url.strip():
        return InviteActionResult("error", "ZITADEL_BASE_URL not configured")
    if not (machine_key_file.strip() or machine_key_json.strip()):
        return InviteActionResult("error", "machine key not configured")

    try:
        token = mint_token_from_settings(
            base_url=base_url,
            machine_key_file=machine_key_file,
            machine_key_json=machine_key_json,
        )
    except Exception as exc:
        logger.exception("invite-action token mint failed user=%s", user_id)
        return InviteActionResult("error", f"token mint: {exc}")

    async with api_client(base_url, token) as client:
        try:
            # Re-read nickname from API when present — event is source of truth for
            # "just set", but confirm user still has that handle.
            current = await get_user_nickname(client, user_id)
            if current is not None:
                try:
                    if normalize_handle(current) != handle:
                        return InviteActionResult(
                            "skipped", "nickName changed since event"
                        )
                except InvalidHandleError:
                    return InviteActionResult("skipped", "current nickName invalid")

            methods = await list_auth_method_types(client, user_id)
            if has_primary_auth_method(methods):
                logger.info(
                    "invite-action skip user=%s: already has primary auth %s",
                    user_id,
                    methods,
                )
                return InviteActionResult("skipped", "user not fresh")

            await create_invite_code(client, user_id)
        except ZitadelApiError as exc:
            logger.warning("invite-action API error user=%s: %s", user_id, exc)
            return InviteActionResult("error", str(exc))
        except httpx.HTTPError as exc:
            logger.warning("invite-action HTTP error user=%s: %s", user_id, exc)
            return InviteActionResult("error", str(exc))

    await store.record_sent(user_id=user_id, handle=handle)
    logger.info("invite-action sent invite user=%s handle=%s", user_id, handle)
    return InviteActionResult("sent", handle)
