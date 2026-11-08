# zitadel-telegram-notifier

Delivers Zitadel HTTP email-provider notifications into private Telegram chats.

Zitadel posts signed payloads to an internal Docker endpoint; Telegram reaches this service only on `https://notifier.zitadel.ascend.<domain>/telegram/webhook`. Console invites put the Telegram username in **Nickname** (`args.nickName`).

Image: `ghcr.io/marmexmander/zitadel-telegram-notifier`

## Endpoints

| Path | Caller | Notes |
|---|---|---|
| `POST /zitadel/hook` | Zitadel (internal) | Verifies `ZITADEL-Signature` (HMAC-SHA256, 300s). Encrypts outbox. Always 2xx after accept. |
| `POST /telegram/webhook` | Telegram | Constant-time `secret_token` check. Private chats only. |
| `GET /health` | probes | Liveness |

## Binding rules

- Match Telegram username to `args.nickName` (strip `@`, casefold, 5–32 `[A-Za-z0-9_]`).
- First matching `/start` pins `chat_id` to `args.preferredLoginName`.
- Unmatched `/start`: *You are not in the system yet. Wait for an invitation from the admin.* (no contact points).
- Private chats only; leave groups. Messages use HTML escape, no link preview, `protect_content`, invite URL as inline button.
- Outbox encrypted at rest under `MASTER_KEY`; deleted after delivery and at ~72h expiry.

## Signing keys

Verified against Zitadel `pkg/actions/signing.go` v4.16.0:

- Header: `ZITADEL-Signature: t=<unix>,v1=<hex>` (multiple `v1` allowed)
- HMAC-SHA256 over ASCII timestamp + `.` + raw body
- 300s tolerance, `hmac.compare_digest`
- Fail closed: service **refuses to start** without an active key; no unsigned/debug mode

Operator CLI (short-lived Zitadel PAT; never used by the running service):

```bash
export MASTER_KEY=...
# Prefer PG_* (infra) or DATABASE_URL override
export PG_HOST=... PG_PORT=5432 PG_USER=zitadel_notify PG_PASSWORD=... PG_DATABASE=zitadel_notify
export ZITADEL_BASE_URL=https://zitadel.ascend.example.com
export ZITADEL_PAT=...   # short-lived
export ZITADEL_PROVIDER_ENDPOINT=http://zitadel-notify:8080/zitadel/hook

python -m cli register   # create + activate HTTP email provider; store signingKey encrypted
python -m cli rotate     # rotate key; previous accepted briefly (SIGNING_KEY_OVERLAP_SECONDS)
python -m cli unlink 'user@org'  # clear Telegram pin for preferredLoginName
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

Required env (aligned with `zitadel_notify.env.j2`): `BOT_TOKEN`, `BOT_MODE=webhook`, `PUBLIC_BASE_URL` (https), `WEBHOOK_SECRET`, `MASTER_KEY`, `ADMIN_IDS`, `HTTP_*`, `LOG_*`, `PG_*`. See `.env.example`.

On startup the service registers the Telegram webhook at `{PUBLIC_BASE_URL}/telegram/webhook`.

## Tests

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
```

Coverage includes signature verification (valid / bad / stale / rotation overlap), unmatched `/start` copy, and outbox delivery after `/start`.

## Assumptions

- Infra (Compose, Traefik, Ansible, Postgres role) lives in the sibling `infra` repo; this tree is a separate git repo at `serv/zitadel_telegram_notifier`.
- Zitadel reaches the notifier at `http://zitadel-notify:8080/zitadel/hook` on the pinned `zitadel` bridge; that URL is what `register` configures.
- Nickname in Console is the Telegram username without a requirement for the user to message the bot first; invites queued before `/start` are delivered when they arrive.
