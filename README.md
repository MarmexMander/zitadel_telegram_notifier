# zitadel-telegram-notifier

[![CI](https://github.com/MarmexMander/zitadel_telegram_notifier/actions/workflows/ci.yml/badge.svg)](https://github.com/MarmexMander/zitadel_telegram_notifier/actions/workflows/ci.yml)

Delivers Zitadel HTTP email-provider notifications into private Telegram chats.

Zitadel posts signed payloads to an internal Docker endpoint; Telegram reaches this service only on `https://notifier.zitadel.ascend.<domain>/telegram/webhook`.

## Addressing: the email field is the route

A user's **email** is `<telegram_username>@telegram` (e.g. `alice_tg@telegram`). The domain has no dot, so it can never be a real mailbox. Username, Nickname and display name stay free.

| Recipient | Meaning |
|---|---|
| `alice_tg@telegram` | Telegram — handled here |
| `alice_tg` / `@alice_tg` | Telegram — a router already stripped the suffix |
| `alice@example.com`, `x@signal`, … | Not ours — logged and ignored |
| `ab@telegram` (bad handle) | Admin alert; delivered only if the login is already pinned |

`app/recipient.py` is the only module that knows this scheme (suffix configurable via `RECIPIENT_SUFFIX`, must be dotless). Everything else works on a `Recipient(channel, handle)`.

### Target layout (not built yet)

```
Zitadel ──HTTP email provider──▶ router ──▶ telegram-notifier   (handle@telegram)
                                       ├──▶ <other>-notifier     (handle@<suffix>)
                                       └──▶ SMTP                 (everything with a dotted domain)
```

The router picks a notifier by suffix and forwards the original signed-payload body. Each notifier accepts either `handle@suffix` or a bare `handle`, so it also runs standalone, as today. Adding a channel means a new container plus a suffix; this one doesn't change.

Nickname is not consulted; only the email field routes.

No custom invite flow is needed: the email field is on Zitadel's V2 create-user form, so create the user with Email `alice_tg@telegram` and tick **Send an invitation**. To attach an existing account, change its email to `x@telegram` and trigger any notification (e.g. email verification, password reset).

Image: `ghcr.io/marmexmander/zitadel-telegram-notifier`

## Endpoints

| Path | Caller | Notes |
|---|---|---|
| `POST /zitadel/hook` | Zitadel (internal) | Verifies `ZITADEL-Signature` (HMAC-SHA256, 300s). Encrypts outbox. Always 2xx after accept. |
| `POST /telegram/webhook` | Telegram | Constant-time `secret_token` check. Private chats only. |
| `GET /health` | probes | Liveness |

## Binding rules

- Match the Telegram username to the recipient handle from `contextInfo.recipientEmailAddress` (strip `@telegram`, casefold, 5–32 `[A-Za-z0-9_]`).
- First matching `/start` pins `chat_id` to `args.preferredLoginName`.
- Unmatched `/start`: localized wait-for-admin copy (no contact points).
- Private chats only; leave groups. Messages use HTML escape, no link preview, `protect_content`, invite URL as inline button.
- Outbox encrypted at rest under `MASTER_KEY`; deleted after delivery and at ~72h expiry.

## Locales

Bot-authored strings (unmatched `/start`, admin invalid-recipient alert, fallback “Open” link label) are localized. Zitadel already renders `templateData` subject/text/buttonText in the user’s language — those are delivered as-is.

**Source of truth:** `args.preferredLanguage` on the HTTP email-provider payload (also `PreferredLanguage` / `preferred_language`, or nested under `args.profile`). Tags normalize to catalog keys (`en-US` → `en`, `uk-UA` → `uk`). When the field is absent (common on stock Zitadel v4.16 webhooks, which use PreferredLanguage for templates but do not always put it in `args`), fallback is the locale stored on the binding/outbox, then **`en`**. Unmatched `/start` has no Zitadel context: default `en`, with Telegram `language_code` as last resort only.

Shipped catalogs: `en`, `uk`. Locale is persisted on outbox rows and bindings; later events refresh the binding when `preferredLanguage` is present.

### Adding a language

1. Add the ISO primary tag to `SUPPORTED_LOCALES` in `app/i18n.py`.
2. Add translations for every msgid in `_CATALOGS` (`unmatched_start`, `admin_invalid_recipient`, `open_link`).
3. Cover normalization + one unmatched `/start` case in `tests/test_i18n.py`.

## Signing keys

Verified against Zitadel `pkg/actions/signing.go` v4.16.0:

- Header: `ZITADEL-Signature: t=<unix>,v1=<hex>` (multiple `v1` allowed)
- HMAC-SHA256 over ASCII timestamp + `.` + raw body
- 300s tolerance, `hmac.compare_digest`
- Fail closed: service **refuses to start** without an active key; no unsigned/debug mode

Operator CLI, bootstrap only — **the running service holds no Zitadel credentials**. Prefer a **machine-user private key** (`ZITADEL_MACHINE_KEY_FILE` / `_JSON`) so the CLI mints a short-lived access token — do not vault a long-lived PAT. Infra: `ansible-playbook playbooks/zitadel_notify_bootstrap.yml` runs `register`.

```bash
export MASTER_KEY=...
# Prefer PG_* (infra) or DATABASE_URL override
export PG_HOST=... PG_PORT=5432 PG_USER=zitadel_notify PG_PASSWORD=... PG_DATABASE=zitadel_notify
export ZITADEL_BASE_URL=https://zitadel.ascend.example.com
export ZITADEL_MACHINE_KEY_JSON='{"type":"serviceaccount","keyId":"...","key":"...","userId":"..."}'
export ZITADEL_PROVIDER_ENDPOINT=http://172.30.50.2:8080/zitadel/hook

python -m cli register              # HTTP email provider + store signingKey
python -m cli rotate                # rotate email-provider key; previous accepted briefly
python -m cli unlink 'user@org'     # clear Telegram pin for preferredLoginName
```

## Build & run

```bash
# Image for GHCR
docker build -t ghcr.io/marmexmander/zitadel-telegram-notifier:latest .
docker push ghcr.io/marmexmander/zitadel-telegram-notifier:latest

# Local (after register has stored a signing key)
export $(grep -v '^#' .env | xargs)
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

Required env (aligned with `zitadel_notify.env.j2`): `BOT_TOKEN`, `BOT_MODE=webhook`, `PUBLIC_BASE_URL` (https), `WEBHOOK_SECRET`, `MASTER_KEY`, `ADMIN_IDS`, `HTTP_*`, `LOG_*`, `PG_*`. Optional: `RECIPIENT_SUFFIX` (default `telegram`). See `.env.example`.

On startup the service registers the Telegram webhook at `{PUBLIC_BASE_URL}/telegram/webhook`.

## Tests

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
```

Coverage includes signature verification (valid / bad / stale / rotation overlap), unmatched `/start` copy (incl. locale fallback), locale extraction/normalization, and outbox delivery after `/start`.

## CI

- **CI** (`.github/workflows/ci.yml`): on PRs and pushes to `main`, runs `pytest` on Python 3.12 (matches the Dockerfile). Optional `ruff` lint is non-blocking.
- **Docker** (`.github/workflows/docker.yml`): on pushes to `main` and tags `v*`, builds and pushes `ghcr.io/marmexmander/zitadel-telegram-notifier` (`sha`, `latest` on main, semver on version tags). Needs `packages: write` for `GITHUB_TOKEN`.

## Assumptions

- Infra (Compose, Traefik, Ansible, Postgres role) lives in the sibling `infra` repo; this tree is a separate git repo at `serv/zitadel_telegram_notifier`.
- Zitadel reaches the notifier at `http://zitadel-notify:8080/zitadel/hook` on the pinned `zitadel` bridge; that URL is what `register` configures.
- Console create: set Email to `<telegram_username>@telegram` and tick “send invite” — the email field is on the V2 create form, so no second step. Messages queued before `/start` deliver when the user arrives.
