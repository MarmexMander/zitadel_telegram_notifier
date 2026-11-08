"""FastAPI entrypoint: Zitadel hook + Telegram webhook."""

from __future__ import annotations

import hmac
import json
import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from fastapi import FastAPI, Header, HTTPException, Request, Response
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.config import Settings, get_settings
from app.crypto import Seal
from app.db import KeyStore, create_engine, create_session_factory, init_db
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
