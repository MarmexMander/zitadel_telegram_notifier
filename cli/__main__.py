"""python -m cli register|rotate|unlink|ensure-invite-action

Auth for register/rotate/ensure-invite-action (prefer machine-user JWT key;
never store a long-lived PAT in vault):

- ZITADEL_MACHINE_KEY_JSON — full Zitadel service-account key JSON → short-lived access token
- ZITADEL_ACCESS_TOKEN — already-minted bearer (seconds–minutes)
- ZITADEL_PAT — legacy alias for a bearer token (discouraged for automation)
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from urllib.parse import quote_plus

import httpx
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.crypto import Seal, fingerprint
from app.db import (
    ActionKeyStore,
    BindingStore,
    KeyStore,
    create_engine,
    create_session_factory,
    init_db,
)
from app.zitadel_auth import load_machine_key_from_env_or_file, mint_access_token


# Pinned bridge IP (not Docker DNS): AddEmailProviderHTTP resolves the host for
# denylist checks while notify may still be down (no signing key → no container).
DEFAULT_ENDPOINT = "http://172.30.50.2:8080/zitadel/hook"
DEFAULT_ACTION_ENDPOINT = "http://172.30.50.2:8080/zitadel/action/invite"
DEFAULT_ACTION_NAME = "telegram-invite-on-nickname"
ACTION_EVENTS = (
    "user.human.profile.changed",
    "user.human.added",
)


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

    zitadel_base_url: str = Field(default="", alias="ZITADEL_BASE_URL")
    zitadel_machine_key_json: str = Field(default="", alias="ZITADEL_MACHINE_KEY_JSON")
    zitadel_machine_key_file: str = Field(default="", alias="ZITADEL_MACHINE_KEY_FILE")
    zitadel_access_token: str = Field(default="", alias="ZITADEL_ACCESS_TOKEN")
    # Legacy name for a bearer token; prefer machine key or short-lived ACCESS_TOKEN.
    zitadel_pat: str = Field(default="", alias="ZITADEL_PAT")
    zitadel_provider_endpoint: str = Field(
        default=DEFAULT_ENDPOINT, alias="ZITADEL_PROVIDER_ENDPOINT"
    )
    zitadel_provider_description: str = Field(
        default="Telegram notifier", alias="ZITADEL_PROVIDER_DESCRIPTION"
    )
    zitadel_provider_id: str | None = Field(default=None, alias="ZITADEL_PROVIDER_ID")
    zitadel_action_endpoint: str = Field(
        default=DEFAULT_ACTION_ENDPOINT, alias="ZITADEL_ACTION_ENDPOINT"
    )
    zitadel_action_name: str = Field(
        default=DEFAULT_ACTION_NAME, alias="ZITADEL_ACTION_NAME"
    )
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

    def require_zitadel_base(self) -> None:
        if not self.zitadel_base_url.strip():
            raise ValueError("ZITADEL_BASE_URL is required")

    def resolve_access_token(self) -> str:
        """Mint or return a bearer token for Admin API calls."""
        self.require_zitadel_base()
        if self.zitadel_machine_key_file.strip() or self.zitadel_machine_key_json.strip():
            machine_key = load_machine_key_from_env_or_file(
                json_env=self.zitadel_machine_key_json,
                file_path=self.zitadel_machine_key_file,
            )
            print(
                "minting Zitadel access token "
                f"(userId={machine_key['userId']} keyId={machine_key['keyId']} "
                f"base={self.zitadel_base_url.rstrip('/')})"
            )
            return mint_access_token(
                base_url=self.zitadel_base_url,
                machine_key=machine_key,
            )
        token = self.zitadel_access_token.strip() or self.zitadel_pat.strip()
        if not token:
            raise ValueError(
                "set ZITADEL_MACHINE_KEY_FILE or ZITADEL_MACHINE_KEY_JSON "
                "(preferred) or ZITADEL_ACCESS_TOKEN / ZITADEL_PAT"
            )
        return token

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


def _client(settings: CliSettings, access_token: str) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=settings.zitadel_base_url.rstrip("/"),
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        timeout=30.0,
    )


def _raise_for_status(resp: httpx.Response, *, action: str) -> None:
    if not resp.is_error:
        return
    detail: object = resp.text
    try:
        detail = resp.json()
    except Exception:
        pass
    raise RuntimeError(f"{action} failed (HTTP {resp.status_code}): {detail}")


async def _find_http_provider(
    client: httpx.AsyncClient, endpoint: str
) -> dict | None:
    resp = await client.post("/admin/v1/email/_search", json={})
    _raise_for_status(resp, action="list email providers")
    for item in resp.json().get("result") or []:
        http = item.get("http") or {}
        if http.get("endpoint") == endpoint:
            return item
    return None


async def _activate(client: httpx.AsyncClient, provider_id: str) -> None:
    activate = await client.post(f"/admin/v1/email/{provider_id}/_activate", json={})
    _raise_for_status(activate, action=f"activate email provider {provider_id}")


async def _rotate_signing_key(
    client: httpx.AsyncClient,
    *,
    provider_id: str,
    endpoint: str,
    description: str,
) -> str:
    update = await client.put(
        f"/admin/v1/email/http/{provider_id}",
        json={
            "endpoint": endpoint,
            "description": description,
            "expirationSigningKey": "0s",
        },
    )
    _raise_for_status(update, action=f"rotate email provider {provider_id}")
    body = update.json()
    signing_key = body.get("signingKey") or body.get("signing_key")
    if not signing_key:
        raise RuntimeError("rotate/update response missing signingKey")
    return signing_key


async def cmd_register(settings: CliSettings) -> int:
    settings.require_master_key()
    access_token = settings.resolve_access_token()
    engine = create_engine(settings.sqlalchemy_url)
    await init_db(engine)
    session_factory = create_session_factory(engine)
    seal = Seal(settings.master_key)
    endpoint = settings.zitadel_provider_endpoint
    description = settings.zitadel_provider_description

    async with session_factory() as session:
        store = KeyStore(session, seal)
        if await store.has_active_key() and await store.get_provider_id():
            provider_id = await store.get_provider_id()
            print(
                f"already registered locally provider id={provider_id}; nothing to do"
            )
            await engine.dispose()
            return 0

    async with _client(settings, access_token) as client:
        existing = await _find_http_provider(client, endpoint)
        if existing:
            provider_id = existing["id"]
            state = existing.get("state") or ""
            if state != "EMAIL_PROVIDER_STATE_ACTIVE":
                await _activate(client, provider_id)
            # DB empty or wiped: force a new signing key into our store.
            signing_key = await _rotate_signing_key(
                client,
                provider_id=provider_id,
                endpoint=endpoint,
                description=description,
            )
            action = "recovered"
        else:
            create = await client.post(
                "/admin/v1/email/http",
                json={"endpoint": endpoint, "description": description},
            )
            _raise_for_status(create, action="add HTTP email provider")
            body = create.json()
            provider_id = body["id"]
            signing_key = body["signingKey"]
            await _activate(client, provider_id)
            action = "registered"

    async with session_factory() as session:
        store = KeyStore(session, seal)
        await store.upsert_provider_meta(
            provider_id=provider_id,
            endpoint=endpoint,
            description=description,
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
    print(
        f"{action} provider id={provider_id} key_fp={fingerprint(signing_key)}"
    )
    print("signing key stored encrypted in DB")
    return 0


async def cmd_rotate(settings: CliSettings) -> int:
    settings.require_master_key()
    access_token = settings.resolve_access_token()
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

    async with _client(settings, access_token) as client:
        signing_key = await _rotate_signing_key(
            client,
            provider_id=provider_id,
            endpoint=settings.zitadel_provider_endpoint,
            description=settings.zitadel_provider_description,
        )

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


async def _find_action_target(
    client: httpx.AsyncClient, name: str
) -> dict | None:
    """Find Actions target by exact name (search API, then filter)."""
    resp = await client.post(
        "/v2/actions/targets/search",
        json={
            "pagination": {"offset": 0, "limit": 100, "asc": True},
            "queries": [
                {
                    "targetNameQuery": {
                        "name": name,
                        "method": "TEXT_QUERY_METHOD_EQUALS",
                    }
                }
            ],
        },
    )
    if resp.status_code == 404:
        # Older builds: fall back to empty query + client filter.
        resp = await client.post(
            "/v2/actions/targets/search",
            json={"pagination": {"offset": 0, "limit": 200, "asc": True}},
        )
    _raise_for_status(resp, action="list action targets")
    body = resp.json()
    targets = body.get("targets") or body.get("result") or []
    for item in targets:
        if item.get("name") == name:
            return item
    return None


async def _set_event_execution(
    client: httpx.AsyncClient, *, event: str, target_id: str
) -> None:
    resp = await client.put(
        "/v2/actions/executions",
        json={
            "condition": {"event": {"event": event}},
            "targets": [target_id],
        },
    )
    _raise_for_status(resp, action=f"set execution for {event}")


async def cmd_ensure_invite_action(settings: CliSettings) -> int:
    """
    Idempotent: create/update Actions v2 target + executions for invite-on-nickname.

    Stores the target signing key encrypted in the notify DB (separate from the
    HTTP email provider key). Machine user needs action.target.* + action.execution.*
    and user.write (CreateInviteCode at runtime).
    """
    settings.require_master_key()
    access_token = settings.resolve_access_token()
    engine = create_engine(settings.sqlalchemy_url)
    await init_db(engine)
    session_factory = create_session_factory(engine)
    seal = Seal(settings.master_key)
    name = settings.zitadel_action_name.strip() or DEFAULT_ACTION_NAME
    endpoint = settings.zitadel_action_endpoint.strip() or DEFAULT_ACTION_ENDPOINT

    async with _client(settings, access_token) as client:
        existing = await _find_action_target(client, name)
        if existing:
            target_id = str(existing["id"])
            signing_key = existing.get("signingKey") or existing.get("signing_key")
            current_endpoint = existing.get("endpoint") or ""
            if current_endpoint != endpoint or not signing_key:
                update = await client.post(
                    f"/v2/actions/targets/{target_id}",
                    json={
                        "name": name,
                        "endpoint": endpoint,
                        "timeout": "15s",
                        "restAsync": {},
                        "payloadType": "PAYLOAD_TYPE_JSON",
                        **(
                            {"expirationSigningKey": "0s"}
                            if not signing_key
                            else {}
                        ),
                    },
                )
                _raise_for_status(update, action=f"update action target {target_id}")
                body = update.json()
                if body.get("signingKey") or body.get("signing_key"):
                    signing_key = body.get("signingKey") or body.get("signing_key")
                if not signing_key:
                    got = await client.get(f"/v2/actions/targets/{target_id}")
                    _raise_for_status(got, action=f"get action target {target_id}")
                    target = got.json().get("target") or got.json()
                    signing_key = target.get("signingKey") or target.get("signing_key")
                action = "updated"
            else:
                action = "existing"
            if not signing_key:
                # Force rotate so we have a key in the DB.
                update = await client.post(
                    f"/v2/actions/targets/{target_id}",
                    json={"expirationSigningKey": "0s"},
                )
                _raise_for_status(update, action=f"rotate action target {target_id}")
                signing_key = update.json().get("signingKey") or update.json().get(
                    "signing_key"
                )
                action = "rotated"
        else:
            create = await client.post(
                "/v2/actions/targets",
                json={
                    "name": name,
                    "endpoint": endpoint,
                    "timeout": "15s",
                    "restAsync": {},
                    "payloadType": "PAYLOAD_TYPE_JSON",
                },
            )
            _raise_for_status(create, action="create action target")
            body = create.json()
            target_id = str(body["id"])
            signing_key = body.get("signingKey") or body.get("signing_key")
            action = "created"

        if not signing_key:
            raise RuntimeError("action target response missing signingKey")

        for event in ACTION_EVENTS:
            await _set_event_execution(client, event=event, target_id=target_id)

    async with session_factory() as session:
        store = ActionKeyStore(session, seal)
        await store.upsert_meta(target_id=target_id, name=name, endpoint=endpoint)
        # Always refresh active key from Zitadel so DB matches what signs webhooks.
        await store.store_active(
            target_id=target_id,
            signing_key=signing_key,
            fingerprint=fingerprint(signing_key),
            demote_previous=True,
            overlap_seconds=settings.signing_key_overlap_seconds,
        )
        await session.commit()

    await engine.dispose()
    print(
        f"{action} action target id={target_id} name={name!r} "
        f"endpoint={endpoint} key_fp={fingerprint(signing_key)}"
    )
    print(f"executions set for: {', '.join(ACTION_EVENTS)}")
    print("action signing key stored encrypted in DB")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m cli",
        description="Operator tools for Zitadel Telegram notifier",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser(
        "register",
        help="Idempotent: create/activate HTTP email provider; store signing key",
    )
    sub.add_parser("rotate", help="Rotate signing key; keep previous briefly in DB")
    sub.add_parser(
        "ensure-invite-action",
        help=(
            "Idempotent: Actions v2 target+executions for invite-on-nickname; "
            "store action signing key"
        ),
    )
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
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if args.command == "rotate":
        try:
            return asyncio.run(cmd_rotate(settings))
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if args.command == "ensure-invite-action":
        try:
            return asyncio.run(cmd_ensure_invite_action(settings))
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if args.command == "unlink":
        return asyncio.run(cmd_unlink(settings, args.preferred_login_name))
    parser.error(f"unknown command {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
