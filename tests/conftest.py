from __future__ import annotations

import os

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

# Ensure settings-dependent imports can resolve secrets during collection.
os.environ.setdefault("MASTER_KEY", "test-master-key-not-for-production")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("BOT_TOKEN", "000000:TEST")
os.environ.setdefault("BOT_MODE", "webhook")
os.environ.setdefault("WEBHOOK_SECRET", "webhook-secret-test")
os.environ.setdefault("PUBLIC_BASE_URL", "https://notifier.zitadel.ascend.example.com")
os.environ.setdefault("ADMIN_IDS", "")
os.environ.setdefault("SKIP_TELEGRAM_WEBHOOK_REGISTER", "true")

from app.config import Settings  # noqa: E402
from app.crypto import Seal  # noqa: E402
from app.db import create_engine, init_db  # noqa: E402


@pytest.fixture
def seal() -> Seal:
    return Seal("test-master-key-not-for-production")


@pytest.fixture
def settings() -> Settings:
    return Settings(  # type: ignore[call-arg]
        MASTER_KEY="test-master-key-not-for-production",
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        BOT_TOKEN="000000:TEST",
        BOT_MODE="webhook",
        WEBHOOK_SECRET="webhook-secret-test",
        PUBLIC_BASE_URL="https://notifier.zitadel.ascend.example.com",
        ADMIN_IDS="",
        SKIP_TELEGRAM_WEBHOOK_REGISTER=True,
    )


@pytest_asyncio.fixture
async def session() -> AsyncSession:
    engine = create_engine("sqlite+aiosqlite:///:memory:")
    await init_db(engine)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as sess:
        yield sess
    await engine.dispose()
