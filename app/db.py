"""Async SQLAlchemy engine, models, and repositories."""

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence

from sqlalchemy import (
    BigInteger,
    DateTime,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Text,
    select,
    update,
)
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.crypto import Seal

metadata = MetaData()


class Base(DeclarativeBase):
    metadata = metadata


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SigningKeyRow(Base):
    __tablename__ = "signing_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    provider_id: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)  # active|previous
    encrypted_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Plain Mapped[datetime] + nullable=True: avoids PEP604/Optional eval bugs on older SQLAlchemy+3.14.
    expires_at = mapped_column(DateTime(timezone=True), nullable=True)


class BindingRow(Base):
    __tablename__ = "bindings"

    preferred_login_name: Mapped[str] = mapped_column(String(320), primary_key=True)
    telegram_user_id: Mapped[int] = mapped_column(BigInteger, nullable=False, unique=True)
    telegram_username: Mapped[str] = mapped_column(String(64), nullable=False)
    pinned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class OutboxRow(Base):
    __tablename__ = "outbox"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    handle: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    preferred_login_name: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    encrypted_payload: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    delivered_at = mapped_column(DateTime(timezone=True), nullable=True)


class ProviderMetaRow(Base):
    """Singleton-ish row for the registered HTTP email provider id."""

    __tablename__ = "provider_meta"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    provider_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    endpoint: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


def create_engine(database_url: str) -> AsyncEngine:
    return create_async_engine(database_url, pool_pre_ping=True)


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def init_db(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


class KeyStore:
    def __init__(self, session: AsyncSession, seal: Seal) -> None:
        self._session = session
        self._seal = seal

    async def list_verification_keys(self) -> list[str]:
        """Active key plus non-expired previous keys (rotation overlap)."""
        now = _utcnow()
        result = await self._session.execute(
            select(SigningKeyRow).where(
                (SigningKeyRow.status == "active")
                | (
                    (SigningKeyRow.status == "previous")
                    & (
                        (SigningKeyRow.expires_at.is_(None))
                        | (SigningKeyRow.expires_at > now)
                    )
                )
            )
        )
        rows = result.scalars().all()
        keys: list[str] = []
        for row in rows:
            keys.append(self._seal.decrypt_str(row.encrypted_key))
        return keys

    async def has_active_key(self) -> bool:
        result = await self._session.execute(
            select(SigningKeyRow.id).where(SigningKeyRow.status == "active").limit(1)
        )
        return result.scalar_one_or_none() is not None

    async def store_active(
        self,
        *,
        provider_id: str,
        signing_key: str,
        fingerprint: str,
        demote_previous: bool = True,
        overlap_seconds: int = 300,
    ) -> None:
        now = _utcnow()
        if demote_previous:
            await self._session.execute(
                update(SigningKeyRow)
                .where(SigningKeyRow.status == "active")
                .values(
                    status="previous",
                    expires_at=now + timedelta(seconds=overlap_seconds),
                )
            )
        row = SigningKeyRow(
            id=str(uuid.uuid4()),
            provider_id=provider_id,
            status="active",
            encrypted_key=self._seal.encrypt(signing_key),
            fingerprint=fingerprint,
            created_at=now,
            expires_at=None,
        )
        self._session.add(row)
        await self._session.flush()

    async def purge_expired_previous(self) -> int:
        now = _utcnow()
        result = await self._session.execute(
            select(SigningKeyRow).where(
                (SigningKeyRow.status == "previous")
                & (SigningKeyRow.expires_at.is_not(None))
                & (SigningKeyRow.expires_at <= now)
            )
        )
        rows = list(result.scalars().all())
        for row in rows:
            await self._session.delete(row)
        return len(rows)

    async def get_provider_id(self) -> str | None:
        result = await self._session.execute(select(ProviderMetaRow).limit(1))
        row = result.scalar_one_or_none()
        return row.provider_id if row else None

    async def upsert_provider_meta(
        self, *, provider_id: str, endpoint: str, description: str
    ) -> None:
        result = await self._session.execute(select(ProviderMetaRow).limit(1))
        row = result.scalar_one_or_none()
        now = _utcnow()
        if row is None:
            self._session.add(
                ProviderMetaRow(
                    provider_id=provider_id,
                    endpoint=endpoint,
                    description=description,
                    updated_at=now,
                )
            )
        else:
            row.provider_id = provider_id
            row.endpoint = endpoint
            row.description = description
            row.updated_at = now
        await self._session.flush()


class BindingStore:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_login(self, preferred_login_name: str) -> BindingRow | None:
        result = await self._session.execute(
            select(BindingRow).where(
                BindingRow.preferred_login_name == preferred_login_name
            )
        )
        return result.scalar_one_or_none()

    async def get_by_telegram_user(self, telegram_user_id: int) -> BindingRow | None:
        result = await self._session.execute(
            select(BindingRow).where(BindingRow.telegram_user_id == telegram_user_id)
        )
        return result.scalar_one_or_none()

    async def pin(
        self,
        *,
        preferred_login_name: str,
        telegram_user_id: int,
        telegram_username: str,
    ) -> BindingRow:
        existing = await self.get_by_login(preferred_login_name)
        if existing is not None:
            return existing
        row = BindingRow(
            preferred_login_name=preferred_login_name,
            telegram_user_id=telegram_user_id,
            telegram_username=telegram_username.casefold(),
            pinned_at=_utcnow(),
        )
        self._session.add(row)
        await self._session.flush()
        return row

    async def unlink(self, preferred_login_name: str) -> bool:
        """Clear Telegram pin for a login. Returns True if a row was deleted."""
        row = await self.get_by_login(preferred_login_name)
        if row is None:
            return False
        await self._session.delete(row)
        await self._session.flush()
        return True


class OutboxStore:
    def __init__(self, session: AsyncSession, seal: Seal) -> None:
        self._session = session
        self._seal = seal

    async def enqueue(
        self,
        *,
        handle: str,
        preferred_login_name: str,
        event_type: str,
        payload: dict[str, Any],
        ttl_hours: int,
    ) -> OutboxRow:
        now = _utcnow()
        row = OutboxRow(
            id=str(uuid.uuid4()),
            handle=handle,
            preferred_login_name=preferred_login_name,
            event_type=event_type,
            encrypted_payload=self._seal.encrypt(
                json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
            ),
            created_at=now,
            expires_at=now + timedelta(hours=ttl_hours),
            delivered_at=None,
        )
        self._session.add(row)
        await self._session.flush()
        return row

    async def pending_for_handle(self, handle: str) -> Sequence[OutboxRow]:
        now = _utcnow()
        result = await self._session.execute(
            select(OutboxRow)
            .where(
                OutboxRow.handle == handle,
                OutboxRow.delivered_at.is_(None),
                OutboxRow.expires_at > now,
            )
            .order_by(OutboxRow.created_at.asc())
        )
        return result.scalars().all()

    async def pending_for_login(self, preferred_login_name: str) -> Sequence[OutboxRow]:
        now = _utcnow()
        result = await self._session.execute(
            select(OutboxRow)
            .where(
                OutboxRow.preferred_login_name == preferred_login_name,
                OutboxRow.delivered_at.is_(None),
                OutboxRow.expires_at > now,
            )
            .order_by(OutboxRow.created_at.asc())
        )
        return result.scalars().all()

    def decrypt_payload(self, row: OutboxRow) -> dict[str, Any]:
        return json.loads(self._seal.decrypt_str(row.encrypted_payload))

    async def mark_delivered(self, row: OutboxRow) -> None:
        row.delivered_at = _utcnow()
        await self._session.delete(row)
        await self._session.flush()

    async def purge_expired(self) -> int:
        now = _utcnow()
        result = await self._session.execute(
            select(OutboxRow).where(OutboxRow.expires_at <= now)
        )
        rows = list(result.scalars().all())
        for row in rows:
            await self._session.delete(row)
        return len(rows)
