"""Minimal Telegram Bot API client (webhook + private-chat delivery)."""

from __future__ import annotations

import html
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class TelegramError(RuntimeError):
    pass


class TelegramClient:
    def __init__(self, bot_token: str, *, timeout: float = 30.0) -> None:
        self._base = f"https://api.telegram.org/bot{bot_token}"
        self._client = httpx.AsyncClient(timeout=timeout)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _call(self, method: str, payload: dict[str, Any]) -> dict[str, Any]:
        response = await self._client.post(f"{self._base}/{method}", json=payload)
        response.raise_for_status()
        data = response.json()
        if not data.get("ok"):
            raise TelegramError(f"telegram {method} failed: {data}")
        return data

    async def set_webhook(self, url: str, secret_token: str) -> None:
        await self._call(
            "setWebhook",
            {
                "url": url,
                "secret_token": secret_token,
                "allowed_updates": ["message", "my_chat_member"],
                "drop_pending_updates": False,
            },
        )
        logger.info("telegram webhook registered")

    async def leave_chat(self, chat_id: int) -> None:
        try:
            await self._call("leaveChat", {"chat_id": chat_id})
        except Exception:
            logger.warning("leaveChat failed for chat_id=%s", chat_id, exc_info=True)

    async def send_text(
        self,
        chat_id: int,
        text: str,
        *,
        reply_markup: dict[str, Any] | None = None,
        protect_content: bool = True,
    ) -> None:
        body: dict[str, Any] = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
            "protect_content": protect_content,
        }
        if reply_markup is not None:
            body["reply_markup"] = reply_markup
        await self._call("sendMessage", body)

    async def send_notification(
        self,
        chat_id: int,
        *,
        subject: str,
        greeting: str,
        body_text: str,
        url: str | None,
        button_text: str | None,
        open_link_label: str = "Open",
    ) -> None:
        safe_subject = html.escape(subject or "Notification")
        safe_greeting = html.escape(greeting or "")
        safe_body = html.escape(body_text or "")
        parts = [f"<b>{safe_subject}</b>"]
        if safe_greeting:
            parts.append(safe_greeting)
        if safe_body:
            parts.append(safe_body)
        markup = None
        if url and button_text:
            markup = {
                "inline_keyboard": [
                    [{"text": button_text, "url": url}],
                ]
            }
        elif url:
            # Zitadel already localized buttonText when present; this label is bot chrome.
            safe_label = html.escape(open_link_label or "Open")
            parts.append(f'<a href="{html.escape(url, quote=True)}">{safe_label}</a>')
        await self.send_text(chat_id, "\n\n".join(parts), reply_markup=markup)

    async def notify_admins(self, admin_chat_ids: list[int], text: str) -> None:
        for chat_id in admin_chat_ids:
            try:
                await self.send_text(chat_id, html.escape(text), protect_content=True)
            except Exception:
                logger.warning("admin alert failed chat_id=%s", chat_id, exc_info=True)
