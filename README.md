# zitadel-telegram-notifier

[![CI](https://github.com/MarmexMander/zitadel_telegram_notifier/actions/workflows/ci.yml/badge.svg)](https://github.com/MarmexMander/zitadel_telegram_notifier/actions/workflows/ci.yml)

Delivers Zitadel HTTP email-provider notifications into private Telegram chats.

Zitadel posts signed payloads to an internal Docker endpoint; Telegram reaches this service only on `https://notifier.zitadel.ascend.<domain>/telegram/webhook`. Console puts the Telegram username in **Nickname**; an Actions v2 event auto-sends the invite for fresh users.

Image: `ghcr.io/marmexmander/zitadel-telegram-notifier`

## Endpoints

| Path | Caller | Notes |
|---|---|---|
| `POST /zitadel/hook` | Zitadel (internal) | Verifies `ZITADEL-Signature` (HMAC-SHA256, 300s). Encrypts outbox. Always 2xx after accept. |
| `POST /zitadel/action/invite` | Zitadel Actions (internal) | Event target: nickname set on a fresh user → `CreateInviteCode`. Separate action signing key. |
| `POST /telegram/webhook` | Telegram | Constant-time `secret_token` check. Private chats only. |
| `GET /health` | probes | Liveness |

## Binding rules

- Match Telegram username to `args.nickName` (strip `@`, casefold, 5–32 `[A-Za-z0-9_]`).
- First matching `/start` pins `chat_id` to `args.preferredLoginName`.
- Unmatched `/start`: localized wait-for-admin copy (no contact points).
- Private chats only; leave groups. Messages use HTML escape, no link preview, `protect_content`, invite URL as inline button.
- Outbox encrypted at rest under `MASTER_KEY`; deleted after delivery and at ~72h expiry.

## Locales

Bot-authored strings (unmatched `/start`, admin invalid-nickname alert, fallback “Open” link label) are localized. Zitadel already renders `templateData` subject/text/buttonText in the user’s language — those are delivered as-is.

**Source of truth:** `args.preferredLanguage` on the HTTP email-provider payload (also `PreferredLanguage` / `preferred_language`, or nested under `args.profile`). Tags normalize to catalog keys (`en-US` → `en`, `uk-UA` → `uk`). When the field is absent (common on stock Zitadel v4.16 webhooks, which use PreferredLanguage for templates but do not always put it in `args`), fallback is the locale stored on the binding/outbox, then **`en`**. Unmatched `/start` has no Zitadel context: default `en`, with Telegram `language_code` as last resort only.

Shipped catalogs: `en`, `uk`. Locale is persisted on outbox rows and bindings; later events refresh the binding when `preferredLanguage` is present.

### Adding a language

1. Add the ISO primary tag to `SUPPORTED_LOCALES` in `app/i18n.py`.
2. Add translations for every msgid in `_CATALOGS` (`unmatched_start`, `admin_invalid_nickname`, `open_link`).
3. Cover normalization + one unmatched `/start` case in `tests/test_i18n.py`.

## Signing keys

Verified against Zitadel `pkg/actions/signing.go` v4.16.0:

- Header: `ZITADEL-Signature: t=<unix>,v1=<hex>` (multiple `v1` allowed)
- HMAC-SHA256 over ASCII timestamp + `.` + raw body
- 300s tolerance, `hmac.compare_digest`
- Fail closed: service **refuses to start** without an active key; no unsigned/debug mode

Operator CLI for bootstrap. Prefer a **machine-user private key** (`ZITADEL_MACHINE_KEY_FILE` / `_JSON`) so the CLI mints a short-lived access token — do not vault a long-lived PAT. Infra: `ansible-playbook playbooks/zitadel_notify_bootstrap.yml` runs `register` then `ensure-invite-action`.

The running service also mounts the machine key to call `CreateInviteCode` from the Actions webhook.

```bash
export MASTER_KEY=...
# Prefer PG_* (infra) or DATABASE_URL override
export PG_HOST=... PG_PORT=5432 PG_USER=zitadel_notify PG_PASSWORD=... PG_DATABASE=zitadel_notify
export ZITADEL_BASE_URL=https://zitadel.ascend.example.com
export ZITADEL_MACHINE_KEY_JSON='{"type":"serviceaccount","keyId":"...","key":"...","userId":"..."}'
export ZITADEL_PROVIDER_ENDPOINT=http://172.30.50.2:8080/zitadel/hook
export ZITADEL_ACTION_ENDPOINT=http://172.30.50.2:8080/zitadel/action/invite

python -m cli register              # HTTP email provider + store signingKey
python -m cli ensure-invite-action  # Actions target+executions + store action signingKey
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

Required env (aligned with `zitadel_notify.env.j2`): `BOT_TOKEN`, `BOT_MODE=webhook`, `PUBLIC_BASE_URL` (https), `WEBHOOK_SECRET`, `MASTER_KEY`, `ADMIN_IDS`, `HTTP_*`, `LOG_*`, `PG_*`, plus runtime `ZITADEL_BASE_URL` + `ZITADEL_MACHINE_KEY_FILE` for invite-on-nickname. See `.env.example`.

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
- Nickname in Console is the Telegram username; set it after create (V2 form has no Nickname). `ensure-invite-action` auto-sends the invite; messages queued before `/start` deliver when the user arrives.
