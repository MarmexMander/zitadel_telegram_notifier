"""python -m cli register|rotate|unlink"""

from __future__ import annotations

import argparse
import asyncio
import sys
from urllib.parse import quote_plus

import httpx
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.crypto import Seal, fingerprint
from app.db import BindingStore, KeyStore, create_engine, create_session_factory, init_db


DEFAULT_ENDPOINT = "http://zitadel-notify:8080/zitadel/hook"


class CliSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", extra="ignore", populate_by_name=True
    )

    master_key: str = Field(default="", alias="MASTER_KEY")
    database_url: str | None = Field(default=None, alias="DATABASE_URL")
    pg_host: str | None = Field(default=None, alias="PG_HOST")
    pg_port: int = Field(default=5432, alias="PG_PORT")
    pg_user: str | None = Field(default=None, alias="PG_USER")
    pg_password: str | None = Field(default=None, alias="PG_PASSWORD")
    pg_database: str | None = Field(default=None, alias="PG_DATABASE")
    pg_sslmode: str = Field(default="disable", alias="PG_SSLMODE")

    # Required for register/rotate only (short-lived PAT; never used by the service).
    zitadel_base_url: str = Field(default="", alias="ZITADEL_BASE_URL")
    zitadel_pat: str = Field(default="", alias="ZITADEL_PAT")
    zitadel_provider_endpoint: str = Field(
        default=DEFAULT_ENDPOINT, alias="ZITADEL_PROVIDER_ENDPOINT"
    )
    zitadel_provider_description: str = Field(
        default="Telegram notifier", alias="ZITADEL_PROVIDER_DESCRIPTION"
    )
    zitadel_provider_id: str | None = Field(default=None, alias="ZITADEL_PROVIDER_ID")
    signing_key_overlap_seconds: int = Field(
        default=300, alias="SIGNING_KEY_OVERLAP_SECONDS"
    )

    @model_validator(mode="after")
    def _require_database(self) -> CliSettings:
        if self.database_url:
            return self
        if not all([self.pg_host, self.pg_user, self.pg_password, self.pg_database]):
            raise ValueError(
                "set DATABASE_URL or PG_HOST/PG_USER/PG_PASSWORD/PG_DATABASE"
            )
        return self

    def require_master_key(self) -> None:
        if not self.master_key.strip():
            raise ValueError("MASTER_KEY is required")

    def require_zitadel_pat(self) -> None:
        if not self.zitadel_base_url.strip() or not self.zitadel_pat.strip():
            raise ValueError("ZITADEL_BASE_URL and ZITADEL_PAT are required")

    @property
    def sqlalchemy_url(self) -> str:
        if self.database_url:
            return self.database_url
        user = quote_plus(self.pg_user or "")
        password = quote_plus(self.pg_password or "")
        return (
            f"postgresql+asyncpg://{user}:{password}"
            f"@{self.pg_host}:{self.pg_port}/{self.pg_database}"
        )


def _client(settings: CliSettings) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=settings.zitadel_base_url.rstrip("/"),
        headers={
            "Authorization": f"Bearer {settings.zitadel_pat}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        timeout=30.0,
    )


async def cmd_register(settings: CliSettings) -> int:
    settings.require_master_key()
    settings.require_zitadel_pat()
    engine = create_engine(settings.sqlalchemy_url)
    await init_db(engine)
    session_factory = create_session_factory(engine)
    seal = Seal(settings.master_key)

    async with _client(settings) as client:
        create = await client.post(
            "/admin/v1/email/http",
            json={
                "endpoint": settings.zitadel_provider_endpoint,
                "description": settings.zitadel_provider_description,
            },
        )
        create.raise_for_status()
        body = create.json()
        provider_id = body["id"]
        signing_key = body["signingKey"]

        activate = await client.post(f"/admin/v1/email/{provider_id}/_activate", json={})
        activate.raise_for_status()

    async with session_factory() as session:
        store = KeyStore(session, seal)
        await store.upsert_provider_meta(
            provider_id=provider_id,
            endpoint=settings.zitadel_provider_endpoint,
            description=settings.zitadel_provider_description,
        )
        await store.store_active(
            provider_id=provider_id,
            signing_key=signing_key,
            fingerprint=fingerprint(signing_key),
            demote_previous=True,
            overlap_seconds=settings.signing_key_overlap_seconds,
        )
        await session.commit()

    await engine.dispose()
    print(f"registered provider id={provider_id} key_fp={fingerprint(signing_key)}")
    print("signing key stored encrypted in DB; clear ZITADEL_PAT from your shell.")
    return 0


async def cmd_rotate(settings: CliSettings) -> int:
    settings.require_master_key()
    settings.require_zitadel_pat()
    engine = create_engine(settings.sqlalchemy_url)
    await init_db(engine)
    session_factory = create_session_factory(engine)
    seal = Seal(settings.master_key)

    async with session_factory() as session:
        store = KeyStore(session, seal)
        provider_id = settings.zitadel_provider_id or await store.get_provider_id()
        if not provider_id:
            print(
                "error: no provider id (set ZITADEL_PROVIDER_ID or run register)",
                file=sys.stderr,
            )
            await engine.dispose()
            return 1

    async with _client(settings) as client:
        # Immediate rotation on Zitadel side ("0s"); we keep previous briefly locally.
        update = await client.put(
            f"/admin/v1/email/http/{provider_id}",
            json={
                "endpoint": settings.zitadel_provider_endpoint,
                "description": settings.zitadel_provider_description,
                "expirationSigningKey": "0s",
            },
        )
        update.raise_for_status()
        body = update.json()
        signing_key = body.get("signingKey") or body.get("signing_key")
        if not signing_key:
            print("error: rotate response missing signingKey", file=sys.stderr)
            await engine.dispose()
            return 1

    async with session_factory() as session:
        store = KeyStore(session, seal)
        await store.upsert_provider_meta(
            provider_id=provider_id,
            endpoint=settings.zitadel_provider_endpoint,
            description=settings.zitadel_provider_description,
        )
        await store.store_active(
            provider_id=provider_id,
            signing_key=signing_key,
            fingerprint=fingerprint(signing_key),
            demote_previous=True,
            overlap_seconds=settings.signing_key_overlap_seconds,
        )
        purged = await store.purge_expired_previous()
        await session.commit()

    await engine.dispose()
    print(
        f"rotated provider id={provider_id} key_fp={fingerprint(signing_key)} "
        f"purged_expired={purged}"
    )
    print(
        "Quiet window: previous key accepted for SIGNING_KEY_OVERLAP_SECONDS. "
        "Re-send any invite lost during rotation."
    )
    return 0


async def cmd_unlink(settings: CliSettings, preferred_login_name: str) -> int:
    engine = create_engine(settings.sqlalchemy_url)
    await init_db(engine)
    session_factory = create_session_factory(engine)

    async with session_factory() as session:
        store = BindingStore(session)
        deleted = await store.unlink(preferred_login_name)
        await session.commit()

    await engine.dispose()
    if deleted:
        print(f"unlinked Telegram pin for login={preferred_login_name!r}")
        return 0
    print(
        f"no binding found for login={preferred_login_name!r}",
        file=sys.stderr,
    )
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m cli",
        description="Operator tools for Zitadel Telegram notifier",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser(
        "register", help="Create + activate HTTP email provider; store signing key"
    )
    sub.add_parser("rotate", help="Rotate signing key; keep previous briefly in DB")
    unlink_parser = sub.add_parser(
        "unlink", help="Clear Telegram pin for a preferredLoginName"
    )
    unlink_parser.add_argument(
        "preferred_login_name",
        help="Zitadel preferredLoginName to unlink (e.g. user@org)",
    )

    args = parser.parse_args(argv)
    try:
        settings = CliSettings()  # type: ignore[call-arg]
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.command == "register":
        try:
            return asyncio.run(cmd_register(settings))
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if args.command == "rotate":
        try:
            return asyncio.run(cmd_rotate(settings))
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if args.command == "unlink":
        return asyncio.run(cmd_unlink(settings, args.preferred_login_name))
    parser.error(f"unknown command {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
