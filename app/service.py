"""Binding + outbox delivery orchestration."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.crypto import Seal
from app.db import BindingStore, OutboxStore
from app.handles import InvalidHandleError, normalize_handle
from app.i18n import DEFAULT_LOCALE, extract_locale, resolve_locale, t
from app.telegram import TelegramClient

logger = logging.getLogger(__name__)


class NotifierService:
    def __init__(
        self,
        session: AsyncSession,
        seal: Seal,
        telegram: TelegramClient,
        settings: Settings,
    ) -> None:
        self._session = session
        self._seal = seal
        self._telegram = telegram
        self._settings = settings
        self.bindings = BindingStore(session)
        self.outbox = OutboxStore(session, seal)

    async def ingest_zitadel_payload(self, payload: dict[str, Any]) -> None:
        args = payload.get("args") or {}
        context = payload.get("contextInfo") or {}
        preferred = str(args.get("preferredLoginName") or args.get("userName") or "")
        event_type = str(context.get("eventType") or "")
        locale = extract_locale(payload) or DEFAULT_LOCALE

        raw_nick = args.get("nickName")
        try:
            handle = normalize_handle(raw_nick if isinstance(raw_nick, str) else None)
        except InvalidHandleError as exc:
            await self._telegram.notify_admins(
                self._settings.admin_id_list,
                t(
                    "admin_invalid_nickname",
                    DEFAULT_LOCALE,
                    login=preferred,
                    error=exc,
                ),
            )
            # Still accept (2xx upstream) — nothing to deliver without a handle
            # unless already pinned by login.
            if preferred:
                binding = await self.bindings.get_by_login(preferred)
                if binding is not None:
                    await self._maybe_refresh_binding_locale(preferred, payload)
                    await self._deliver_payload(binding.telegram_user_id, payload, binding.locale)
                    return
            logger.warning("dropping notification: invalid handle login=%r", preferred)
            return

        if not preferred:
            preferred = handle

        row = await self.outbox.enqueue(
            handle=handle,
            preferred_login_name=preferred,
            event_type=event_type,
            payload=payload,
            ttl_hours=self._settings.outbox_ttl_hours,
            locale=locale,
        )

        binding = await self.bindings.get_by_login(preferred)
        if binding is not None:
            await self._maybe_refresh_binding_locale(preferred, payload)
            await self._deliver_row(binding.telegram_user_id, row, binding.locale)
            return

        logger.info(
            "queued outbox id=%s handle=%s login=%s locale=%s (awaiting /start)",
            row.id,
            handle,
            preferred,
            locale,
        )

    async def handle_telegram_update(self, update: dict[str, Any]) -> None:
        message = update.get("message") or {}
        chat = message.get("chat") or {}
        chat_type = chat.get("type")
        chat_id = chat.get("id")

        # Private chats only; leave groups/supergroups/channels.
        if chat_type and chat_type != "private" and chat_id is not None:
            await self._telegram.leave_chat(int(chat_id))
            return

        if chat_type != "private":
            return

        text = (message.get("text") or "").strip()
        if not text.startswith("/start"):
            return

        user = message.get("from") or {}
        telegram_user_id = user.get("id")
        username = user.get("username")
        if telegram_user_id is None:
            return

        tg_lang = user.get("language_code")
        if isinstance(tg_lang, str):
            telegram_language_code = tg_lang
        else:
            telegram_language_code = None

        async def _unmatched() -> None:
            # No Zitadel payload: default en; Telegram language_code last resort only.
            locale = resolve_locale(telegram_language_code=telegram_language_code)
            await self._telegram.send_text(
                int(telegram_user_id),
                t("unmatched_start", locale),
            )

        if not username:
            await _unmatched()
            return

        try:
            handle = normalize_handle(username)
        except InvalidHandleError:
            await _unmatched()
            return

        pending = await self.outbox.pending_for_handle(handle)
        if not pending:
            await _unmatched()
            return

        # Pin on first matching /start using preferredLoginName from the oldest pending.
        first_payload = self.outbox.decrypt_payload(pending[0])
        args = first_payload.get("args") or {}
        preferred = str(
            args.get("preferredLoginName")
            or pending[0].preferred_login_name
            or handle
        )
        locale = resolve_locale(
            payload=first_payload,
            stored=pending[0].locale,
        )
        await self.bindings.pin(
            preferred_login_name=preferred,
            telegram_user_id=int(telegram_user_id),
            telegram_username=handle,
            locale=locale,
        )

        for row in pending:
            await self._deliver_row(int(telegram_user_id), row, locale)

        # Also drain any other pending for the same login (different handle spelling edge).
        for row in await self.outbox.pending_for_login(preferred):
            row_locale = resolve_locale(payload=self.outbox.decrypt_payload(row), stored=locale)
            await self._deliver_row(int(telegram_user_id), row, row_locale)

    async def _maybe_refresh_binding_locale(
        self, preferred_login_name: str, payload: dict[str, Any]
    ) -> None:
        """Prefer latest preferredLanguage from the payload when present."""
        locale = extract_locale(payload)
        if locale is None:
            return
        await self.bindings.set_locale(preferred_login_name, locale)

    async def _deliver_row(self, chat_id: int, row: Any, stored_locale: str) -> None:
        payload = self.outbox.decrypt_payload(row)
        locale = resolve_locale(payload=payload, stored=stored_locale or row.locale)
        await self._deliver_payload(chat_id, payload, locale)
        await self.outbox.mark_delivered(row)

    async def _deliver_payload(
        self, chat_id: int, payload: dict[str, Any], stored_locale: str
    ) -> None:
        template = payload.get("templateData") or {}
        locale = resolve_locale(payload=payload, stored=stored_locale)
        # templateData subject/text/buttonText are already localized by Zitadel.
        # Only bot chrome (fallback Open label) uses our catalogs.
        await self._telegram.send_notification(
            chat_id,
            subject=str(template.get("subject") or template.get("title") or "Notification"),
            greeting=str(template.get("greeting") or ""),
            body_text=str(template.get("text") or ""),
            url=template.get("url"),
            button_text=template.get("buttonText"),
            open_link_label=t("open_link", locale),
        )
