"""Runtime configuration. Fail closed: no unsigned/debug mode.

Env names match compose/apps/zitadel_notify/zitadel_notify.env.j2.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from urllib.parse import quote_plus

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
        populate_by_name=True,
    )

    master_key: str = Field(..., alias="MASTER_KEY")

    bot_token: str = Field(..., alias="BOT_TOKEN")
    bot_mode: str = Field(default="webhook", alias="BOT_MODE")
    webhook_secret: str = Field(..., alias="WEBHOOK_SECRET")
    public_base_url: str = Field(..., alias="PUBLIC_BASE_URL")
    admin_ids: str = Field(default="", alias="ADMIN_IDS")

    http_host: str = Field(default="0.0.0.0", alias="HTTP_HOST")
    http_port: int = Field(default=8080, alias="HTTP_PORT")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_format: str = Field(default="json", alias="LOG_FORMAT")

    # Prefer PG_* (infra); DATABASE_URL optional override (tests / local).
    database_url: str | None = Field(default=None, alias="DATABASE_URL")
    pg_host: str | None = Field(default=None, alias="PG_HOST")
    pg_port: int = Field(default=5432, alias="PG_PORT")
    pg_user: str | None = Field(default=None, alias="PG_USER")
    pg_password: str | None = Field(default=None, alias="PG_PASSWORD")
    pg_database: str | None = Field(default=None, alias="PG_DATABASE")
    pg_sslmode: str = Field(default="disable", alias="PG_SSLMODE")

    outbox_ttl_hours: int = Field(default=72, alias="OUTBOX_TTL_HOURS")
    signing_key_overlap_seconds: int = Field(
        default=300, alias="SIGNING_KEY_OVERLAP_SECONDS"
    )
    signature_tolerance_seconds: int = Field(
        default=300, alias="SIGNATURE_TOLERANCE_SECONDS"
    )
    skip_telegram_webhook_register: bool = Field(
        default=False, alias="SKIP_TELEGRAM_WEBHOOK_REGISTER"
    )

    @field_validator("public_base_url")
    @classmethod
    def _https_public_base(cls, value: str) -> str:
        value = value.rstrip("/")
        if not value.startswith("https://"):
            raise ValueError("PUBLIC_BASE_URL must be https://...")
        return value

    @field_validator("master_key", "bot_token", "webhook_secret")
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("required secret must be non-empty")
        return value.strip()

    @field_validator("bot_mode")
    @classmethod
    def _webhook_only(cls, value: str) -> str:
        mode = value.strip().lower()
        if mode != "webhook":
            raise ValueError("BOT_MODE must be 'webhook' (long polling is not supported)")
        return mode

    @model_validator(mode="after")
    def _require_database(self) -> Settings:
        if self.database_url:
            return self
        missing = [
            name
            for name, val in (
                ("PG_HOST", self.pg_host),
                ("PG_USER", self.pg_user),
                ("PG_PASSWORD", self.pg_password),
                ("PG_DATABASE", self.pg_database),
            )
            if not val
        ]
        if missing:
            raise ValueError(
                "set DATABASE_URL or PG_HOST/PG_USER/PG_PASSWORD/PG_DATABASE "
                f"(missing: {', '.join(missing)})"
            )
        return self

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

    @property
    def admin_id_list(self) -> list[int]:
        if not self.admin_ids.strip():
            return []
        return [int(part.strip()) for part in self.admin_ids.split(",") if part.strip()]

    @property
    def telegram_webhook_url(self) -> str:
        return f"{self.public_base_url}/telegram/webhook"

    def configure_logging(self) -> None:
        level = getattr(logging, self.log_level.upper(), logging.INFO)
        fmt = "%(asctime)s %(levelname)s %(name)s %(message)s"
        logging.basicConfig(level=level, format=fmt, force=True)


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
