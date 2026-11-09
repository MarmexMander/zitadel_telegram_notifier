"""FastAPI entrypoint: Zitadel hook + Telegram webhook."""

from __future__ import annotations

import hmac
import json
import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from fastapi import FastAPI, Header, HTTPException, Request, Response
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.action_invite import handle_profile_event
from app.config import Settings, get_settings
from app.crypto import Seal
from app.db import (
    ActionKeyStore,
    AutoInviteStore,
    KeyStore,
    create_engine,
    create_session_factory,
    init_db,
)
from app.service import NotifierService
from app.signature import SignatureError, validate_payload
from app.telegram import TelegramClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger(__name__)


class AppState:
    settings: Settings
    engine: AsyncEngine
    session_factory: async_sessionmaker[AsyncSession]
    seal: Seal
    telegram: TelegramClient


state = AppState()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    settings.configure_logging()
    state.settings = settings
    state.seal = Seal(settings.master_key)
    state.engine = create_engine(settings.sqlalchemy_url)
    state.session_factory = create_session_factory(state.engine)
    state.telegram = TelegramClient(settings.bot_token)

    await init_db(state.engine)

    async with state.session_factory() as session:
        keys = KeyStore(session, state.seal)
        if not await keys.has_active_key():
            await state.telegram.aclose()
            await state.engine.dispose()
            raise RuntimeError(
                "refusing to start: no active Zitadel signing key in DB; "
                "run `python -m cli register` first"
            )

    if not settings.skip_telegram_webhook_register:
        await state.telegram.set_webhook(
            settings.telegram_webhook_url,
            settings.webhook_secret,
        )
    else:
        logger.warning("SKIP_TELEGRAM_WEBHOOK_REGISTER set; webhook not registered")

    logger.info("zitadel-telegram-notifier ready")
    try:
        yield
    finally:
        await state.telegram.aclose()
        await state.engine.dispose()


app = FastAPI(
    title="zitadel-telegram-notifier",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/zitadel/hook")
async def zitadel_hook(
    request: Request,
    zitadel_signature: str | None = Header(default=None, alias="ZITADEL-Signature"),
) -> Response:
    raw = await request.body()

    async with state.session_factory() as session:
        keystore = KeyStore(session, state.seal)
        signing_keys = await keystore.list_verification_keys()
        try:
            validate_payload(
                raw,
                zitadel_signature,
                signing_keys,
                tolerance_seconds=state.settings.signature_tolerance_seconds,
            )
        except SignatureError:
            # Never log the body.
            logger.warning("rejected zitadel hook: signature verification failed")
            raise HTTPException(status_code=401, detail="invalid signature") from None

        try:
            payload: dict[str, Any] = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise HTTPException(status_code=400, detail="invalid json") from None

        service = NotifierService(session, state.seal, state.telegram, state.settings)
        await service.ingest_zitadel_payload(payload)
        await keystore.purge_expired_previous()
        await service.outbox.purge_expired()
        await session.commit()

    # Always 2xx after accept into outbox (even if user has not /start'd yet).
    return Response(status_code=204)


@app.post("/zitadel/action/invite")
async def zitadel_action_invite(
    request: Request,
    zitadel_signature: str | None = Header(default=None, alias="ZITADEL-Signature"),
    x_zitadel_signature: str | None = Header(
        default=None, alias="X-ZITADEL-Signature"
    ),
) -> Response:
    """
    Actions v2 event target: auto CreateInviteCode when Nickname is set on a fresh user.

    Registered by `python -m cli ensure-invite-action` (bootstrap playbook step).
    """
    raw = await request.body()
    header = zitadel_signature or x_zitadel_signature

    async with state.session_factory() as session:
        action_keys = ActionKeyStore(session, state.seal)
        signing_keys = await action_keys.list_verification_keys()
        if not signing_keys:
            logger.warning("rejected action invite: no action signing key (run ensure-invite-action)")
            raise HTTPException(status_code=503, detail="action signing key missing")
        try:
            validate_payload(
                raw,
                header,
                signing_keys,
                tolerance_seconds=state.settings.signature_tolerance_seconds,
            )
        except SignatureError:
            logger.warning("rejected action invite: signature verification failed")
            raise HTTPException(status_code=401, detail="invalid signature") from None

        try:
            payload: dict[str, Any] = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise HTTPException(status_code=400, detail="invalid json") from None

        result = await handle_profile_event(
            body=payload,
            store=AutoInviteStore(session),
            base_url=state.settings.zitadel_base_url,
            machine_key_file=state.settings.zitadel_machine_key_file,
            machine_key_json=state.settings.zitadel_machine_key_json,
        )
        await session.commit()

    if result.status == "error":
        # 5xx so operators see failures; async targets ignore body.
        logger.error("action invite handler error: %s", result.detail)
        raise HTTPException(status_code=502, detail="invite action failed")
    return Response(status_code=204)


@app.post("/telegram/webhook")
async def telegram_webhook(
    request: Request,
    x_telegram_bot_api_secret_token: str | None = Header(
        default=None, alias="X-Telegram-Bot-Api-Secret-Token"
    ),
) -> Response:
    expected = state.settings.webhook_secret
    provided = x_telegram_bot_api_secret_token or ""
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="invalid secret_token")

    try:
        update = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid json") from None

    async with state.session_factory() as session:
        service = NotifierService(session, state.seal, state.telegram, state.settings)
        await service.handle_telegram_update(update)
        await session.commit()

    return Response(status_code=204)
