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
    text,
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
    # Normalized catalog key (en/uk); refreshed from Zitadel preferredLanguage when present.
    locale: Mapped[str] = mapped_column(String(16), nullable=False, default="en")
    pinned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class OutboxRow(Base):
    __tablename__ = "outbox"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    handle: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    preferred_login_name: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    # Normalized locale from payload at enqueue (default en when absent).
    locale: Mapped[str] = mapped_column(String(16), nullable=False, default="en")
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


class ActionMetaRow(Base):
    """Singleton-ish row for the Actions v2 target that auto-sends invites."""

    __tablename__ = "action_meta"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    endpoint: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ActionSigningKeyRow(Base):
    """Signing keys for the Actions target (separate from HTTP email provider keys)."""

    __tablename__ = "action_signing_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target_id: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)  # active|previous
    encrypted_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at = mapped_column(DateTime(timezone=True), nullable=True)


class AutoInviteRow(Base):
    """Idempotency: one auto-invite per user_id + handle pair."""

    __tablename__ = "auto_invites"

    user_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    handle: Mapped[str] = mapped_column(String(64), nullable=False)
    sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


def create_engine(database_url: str) -> AsyncEngine:
    return create_async_engine(database_url, pool_pre_ping=True)


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def init_db(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_ensure_locale_columns)


def _ensure_locale_columns(sync_conn: Any) -> None:
    """Add locale columns on existing DBs created before i18n (create_all is no-op)."""
    for table in ("bindings", "outbox"):
        if _has_column(sync_conn, table, "locale"):
            continue
        sync_conn.exec_driver_sql(
            f"ALTER TABLE {table} ADD COLUMN locale VARCHAR(16) NOT NULL DEFAULT 'en'"
        )


def _has_column(sync_conn: Any, table: str, column: str) -> bool:
    # Allowlist only — identifiers are not end-user input.
    if table not in {"bindings", "outbox"} or not column.isidentifier():
        raise ValueError(f"refusing column probe for {table!r}.{column!r}")
    dialect = sync_conn.dialect.name
    if dialect == "sqlite":
        rows = sync_conn.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()
        return any(row[1] == column for row in rows)
    # exec_driver_sql uses DBAPI paramstyle; :name is SQLAlchemy text() only
    # and blows up under asyncpg ("syntax error at or near ':'").
    rows = sync_conn.execute(
        text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = :table_name AND column_name = :column_name"
        ),
        {"table_name": table, "column_name": column},
    ).fetchall()
    return bool(rows)


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


class ActionKeyStore:
    """Encrypted Actions target signing keys + meta (isolated from email provider keys)."""

    def __init__(self, session: AsyncSession, seal: Seal) -> None:
        self._session = session
        self._seal = seal

    async def list_verification_keys(self) -> list[str]:
        now = _utcnow()
        result = await self._session.execute(
            select(ActionSigningKeyRow).where(
                (ActionSigningKeyRow.status == "active")
                | (
                    (ActionSigningKeyRow.status == "previous")
                    & (
                        (ActionSigningKeyRow.expires_at.is_(None))
                        | (ActionSigningKeyRow.expires_at > now)
                    )
                )
            )
        )
        rows = result.scalars().all()
        return [self._seal.decrypt_str(row.encrypted_key) for row in rows]

    async def has_active_key(self) -> bool:
        result = await self._session.execute(
            select(ActionSigningKeyRow.id)
            .where(ActionSigningKeyRow.status == "active")
            .limit(1)
        )
        return result.scalar_one_or_none() is not None

    async def store_active(
        self,
        *,
        target_id: str,
        signing_key: str,
        fingerprint: str,
        demote_previous: bool = True,
        overlap_seconds: int = 300,
    ) -> None:
        now = _utcnow()
        if demote_previous:
            await self._session.execute(
                update(ActionSigningKeyRow)
                .where(ActionSigningKeyRow.status == "active")
                .values(
                    status="previous",
                    expires_at=now + timedelta(seconds=overlap_seconds),
                )
            )
        self._session.add(
            ActionSigningKeyRow(
                id=str(uuid.uuid4()),
                target_id=target_id,
                status="active",
                encrypted_key=self._seal.encrypt(signing_key),
                fingerprint=fingerprint,
                created_at=now,
                expires_at=None,
            )
        )
        await self._session.flush()

    async def get_target_id(self) -> str | None:
        result = await self._session.execute(select(ActionMetaRow).limit(1))
        row = result.scalar_one_or_none()
        return row.target_id if row else None

    async def upsert_meta(
        self, *, target_id: str, name: str, endpoint: str
    ) -> None:
        result = await self._session.execute(select(ActionMetaRow).limit(1))
        row = result.scalar_one_or_none()
        now = _utcnow()
        if row is None:
            self._session.add(
                ActionMetaRow(
                    target_id=target_id,
                    name=name,
                    endpoint=endpoint,
                    updated_at=now,
                )
            )
        else:
            row.target_id = target_id
            row.name = name
            row.endpoint = endpoint
            row.updated_at = now
        await self._session.flush()


class AutoInviteStore:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def already_sent(self, *, user_id: str, handle: str) -> bool:
        result = await self._session.execute(
            select(AutoInviteRow).where(AutoInviteRow.user_id == user_id)
        )
        row = result.scalar_one_or_none()
        if row is None:
            return False
        return row.handle == handle

    async def record_sent(self, *, user_id: str, handle: str) -> None:
        result = await self._session.execute(
            select(AutoInviteRow).where(AutoInviteRow.user_id == user_id)
        )
        row = result.scalar_one_or_none()
        now = _utcnow()
        if row is None:
            self._session.add(
                AutoInviteRow(user_id=user_id, handle=handle, sent_at=now)
            )
        else:
            row.handle = handle
            row.sent_at = now
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
        locale: str = "en",
    ) -> BindingRow:
        existing = await self.get_by_login(preferred_login_name)
        if existing is not None:
            if locale and existing.locale != locale:
                existing.locale = locale
                await self._session.flush()
            return existing
        row = BindingRow(
            preferred_login_name=preferred_login_name,
            telegram_user_id=telegram_user_id,
            telegram_username=telegram_username.casefold(),
            locale=locale or "en",
            pinned_at=_utcnow(),
        )
        self._session.add(row)
        await self._session.flush()
        return row

    async def set_locale(self, preferred_login_name: str, locale: str) -> None:
        row = await self.get_by_login(preferred_login_name)
        if row is None or row.locale == locale:
            return
        row.locale = locale
        await self._session.flush()

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
        locale: str = "en",
    ) -> OutboxRow:
        now = _utcnow()
        row = OutboxRow(
            id=str(uuid.uuid4()),
            handle=handle,
            preferred_login_name=preferred_login_name,
            event_type=event_type,
            locale=locale or "en",
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
