# WhatsApp MCP for ChatGPT Dot

**Connect your ChatGPT Dot to WhatsApp.** A self-hosted WhatsApp MCP server that lets a ChatGPT Dot (and any ChatGPT app or MCP connector) read your personal WhatsApp chats, get pushed new messages in real time via **MCP Events** webhooks, and send replies, with server-enforced allowlists and a daily send cap.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)
![Dependencies: none](https://img.shields.io/badge/dependencies-stdlib%20only-brightgreen.svg)
![Deploy: docker compose](https://img.shields.io/badge/deploy-docker%20compose-2496ED.svg)
![MCP](https://img.shields.io/badge/MCP-tools%20%2B%20events-black.svg)

- **One file, zero dependencies.** `app.py` is ~1,100 lines of Python standard library. Nothing to `pip install`, easy to audit.
- **Push, not poll.** Incoming messages are delivered to ChatGPT as MCP Events (Standard Webhooks HMAC, durable SQLite outbox, retries, replay cursor).
- **Works with ChatGPT out of the box.** OAuth 2.1 with Dynamic Client Registration and PKCE S256, Streamable HTTP transport.
- **Privacy boundary on the server.** Groups, status and channels never match. Read and send scopes, new-chat sending and the daily cap are set in env, never by the model.
- **Built on [WAHA](https://waha.devlike.pro/)** (GOWS engine). You link WhatsApp as a companion device; no Business API account needed.

## How it works

```
WhatsApp ── WAHA (GOWS) ──webhook──▶ app.py ──MCP Events webhook──▶ ChatGPT
                ▲                     │  SQLite: messages, outbox, OAuth
                └──── sendText ◀──────┘◀── MCP tools (OAuth 2.1) ─── ChatGPT
```

1. WAHA keeps a linked-device session and posts each incoming message to the bridge (HMAC-signed).
2. The bridge stores messages from allowed chats, commits, then enqueues one event per matching subscription.
3. A delivery worker POSTs events to ChatGPT's callback, in order per subscription, with exponential backoff.
4. ChatGPT calls tools to read a chat or send a reply. Every call is checked against the allowlists.
5. Every 10 minutes, and whenever the session reconnects, the bridge pulls recent history and ingests anything the webhook missed.

## Quick start

Requirements: a Linux server with Docker, a domain with HTTPS (Caddy, Traefik, nginx or Cloudflare Tunnel), and a phone with WhatsApp.

```bash
git clone https://github.com/ohld/whatsapp-mcp-chatgpt-dot && cd whatsapp-mcp-chatgpt-dot
cp .env.example .env
```

Generate the secrets and paste them into `.env`:

```bash
python3 - <<'PY'
import hashlib, getpass, secrets
key = secrets.token_urlsafe(32)
print("OWNER_PASSWORD_SHA256=" + hashlib.sha256(getpass.getpass("OAuth password: ").encode()).hexdigest())
print("WAHA_API_KEY=" + key)
print("WAHA_API_KEY_HASH=sha512:" + hashlib.sha512(key.encode()).hexdigest())
print("WAHA_WEBHOOK_HMAC=" + secrets.token_urlsafe(32))
print("WAHA_DASHBOARD_PASSWORD=" + secrets.token_urlsafe(16))
PY
```

Start it and create the WhatsApp session:

```bash
docker compose up -d
docker compose exec bridge python /app/app.py setup-session
```

Link WhatsApp: open an SSH tunnel (`ssh -L 3000:127.0.0.1:3000 your-server`), open `http://localhost:3000/dashboard`, log in with the dashboard credentials, and scan the QR code from your phone (WhatsApp → Linked devices). `docker compose exec bridge python /app/app.py status` should show `session_status: WORKING`.

Point your reverse proxy at `127.0.0.1:8080` so that `PUBLIC_URL` serves the bridge over HTTPS.

## How to connect your ChatGPT Dot to WhatsApp

There is no official WhatsApp connector for ChatGPT Dots. This server fills that gap: the Dot gets WhatsApp tools plus a live feed of incoming messages.

1. Deploy the bridge (see [Quick start](#quick-start)) and link your phone.
2. In ChatGPT, enable developer mode and create a new app (MCP connector) with URL `https://<your PUBLIC_URL>/mcp` and OAuth authentication. ChatGPT registers itself automatically.
3. Enter your owner password on the consent page.
4. Add the app to your Dot. The Dot subscribes to the `whatsapp.message.received` event and wakes up on every new personal message.
5. Tell the Dot what to do, for example: *"When a client writes on WhatsApp, summarize it for me and draft a reply; send only after I confirm."*

The same app works in a regular ChatGPT chat: *"What did I get on WhatsApp in the last hour?"*

Other MCP clients that support OAuth work too. Add their redirect origin to `OAUTH_REDIRECT_PREFIXES` (for example `https://claude.ai/`).

## Tools and events

| Tool | What it does |
|---|---|
| `whatsapp_status` | Connection state, read/send scope, delivery backlog |
| `whatsapp_recent_chats` | Most recently active personal chats, with names and `sendAllowed` |
| `whatsapp_read_chat` | Last 1–30 messages of one allowed chat, both directions |
| `whatsapp_get_message` | Full text of a received message by id |
| `whatsapp_resolve_phone` | Check whether a `+country` number is on WhatsApp and get its chat id; sends nothing |
| `whatsapp_send_message` | Send text to an allowed chat or `+country` number; requires an `idempotencyKey` |

| Event | Payload |
|---|---|
| `whatsapp.message.received` | `messageId`, `chatId`, `sender`, `senderName`, `text`, `hasMedia`. Optional filter: `chatIds`. Replayable by cursor. |
| `whatsapp.connection.changed` | `status`, `previousStatus` (anything except `WORKING` means messages are not arriving) |

Text from business templates, buttons and lists is extracted too. Media is flagged (`hasMedia`) but never downloaded.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `PUBLIC_URL` | required | Public HTTPS origin. Also the OAuth issuer, so keep it stable. |
| `OWNER_NAME` | `the owner` | Name used in tool descriptions, model instructions and the consent page |
| `OWNER_PASSWORD_SHA256` | — | SHA-256 hex of the consent-page password. Empty disables login. |
| `ALLOWED_CHATS` | `synthetic:test` | Comma list of chat ids, or `*` for every personal chat |
| `SEND_CHATS` | `synthetic:test` | Comma list, or `*` for chats with existing history |
| `SEND_ENABLED` | `true` | Master switch for sending |
| `SEND_NEW_CHATS` | `false` | With `SEND_CHATS=*`, also allow first messages to new numbers |
| `SEND_DAILY_CAP` | `30` | Max sends per rolling 24 hours |
| `RETENTION_DAYS` | `30` | Stored message retention |
| `OAUTH_REDIRECT_PREFIXES` | `https://chatgpt.com/` | Allowed OAuth redirect URI prefixes, comma-separated |
| `WAHA_API_KEY` / `WAHA_API_KEY_HASH` | — | Bridge ↔ WAHA auth (plain key / `sha512:` hash) |
| `WAHA_WEBHOOK_HMAC` | — | Signs WAHA → bridge webhooks |

Scope changes require a container recreate (`docker compose up -d`); `docker restart` does not reload env.

## Is it safe?

Read this before you connect a model to your messages.

- **Prompt injection is the main risk.** Anyone who can message you can write text that tries to steer the model, for example to read another chat and forward it. The bridge labels message text as untrusted, limits scope and rate, and never lets the model change its own permissions. It cannot prove that you, rather than an incoming message, asked for a send. Keep `SEND_NEW_CHATS=false` and narrow `SEND_CHATS` if that matters to you.
- **Single owner.** Every valid OAuth token acts as you. Revoke all of them with `app.py revoke-tokens`.
- **WhatsApp terms.** WAHA uses the multi-device protocol as an unofficial client. WhatsApp may restrict accounts that automate messaging. The default send cap keeps you at human scale; do not use this for bulk messaging.
- **What is stored:** messages from allowed chats (default 30 days), OAuth token hashes, the event outbox. Message text is never logged. The `waha-sessions` volume is your WhatsApp login: treat it as a credential.
- **Network:** WAHA is never exposed publicly. Event callbacks must be HTTPS to a public IP; the bridge connects to the validated IP, keeps SNI and never follows redirects.

## Operations

```bash
docker compose exec bridge python /app/app.py status                        # session, subscriptions, outbox
docker compose exec bridge python /app/app.py synthetic synthetic:test "hi" # fake incoming message, end-to-end test
docker compose exec bridge python /app/app.py find-chat 15551234567         # map a phone number to a chat id
docker compose exec bridge python /app/app.py revoke-tokens                 # log every client out
```

Unlink: phone → Linked devices → log out, then `docker compose down -v` to delete the session volume.

### Coolify

Paste `docker-compose.coolify.yml` as a Docker Compose service (it inlines `app.py`) and set the env variables in Coolify. Coolify does not rewrite an existing inline file: to update code on a running service, copy the new `app.py` over the service's `app.py` on the host and restart the bridge.

## Delivery guarantees

- WAHA → bridge: WAHA retries 15 times with exponential backoff; the bridge commits before it acknowledges.
- Missed messages: reconciliation pulls the last 30 messages of each active chat, deduplicated by message id. Messages are lost only if more than 30 arrive in one chat during an outage.
- Bridge → ChatGPT: Standard Webhooks signatures, one event per POST, head-of-line per subscription, backoff up to 1 hour, 25 attempts, no retry on 410/413. Subscriptions accept a cursor and replay up to 100 missed events.

## Development

```bash
python3 test_recipients.py && python3 test_bridge.py   # stdlib unittest, runs a real server against fakes
python3 build_compose.py                               # regenerate both compose files after editing app.py
```

`app.py` must not contain `$` because Coolify interpolates it in the inlined compose file; `build_compose.py` checks this.

## FAQ

**Does it need the WhatsApp Business API?** No. It links to your normal WhatsApp or WhatsApp Business app as a companion device through WAHA.

**Can it read group chats?** No. Only personal chats match, by design.

**Does it work with Claude, Cursor or other MCP clients?** Tools work with any MCP client that supports OAuth and Streamable HTTP. Push delivery needs a client that implements MCP Events webhooks.

**What is a ChatGPT Dot?** An always-on ChatGPT agent that runs in the background and uses apps (MCP connectors). With this server it can react to WhatsApp messages as they arrive.

**Why not poll?** Polling wakes the model for nothing and misses the moment. Events let a Dot react to a message within seconds.

## License

[MIT](LICENSE)

---

Built by Dan Okhlopkov · [okhlopkov.com](https://okhlopkov.com) · [X: @danokhlopkov](https://x.com/danokhlopkov)
