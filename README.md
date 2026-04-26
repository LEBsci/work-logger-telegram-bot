# Work Logger Telegram Bot

A Telegram bot for tracking work hours. Users log in and out via a persistent keyboard, and can request a summary of hours worked today, this week, or this month.

## Features

- **Log In / Log Out** — one-tap time tracking via a persistent reply keyboard
- **Summary** — breakdown of hours worked today, this week, and this month; counts an open session if the user is currently logged in
- **Admin approval** — new users must be approved before they can use the bot; the admin receives an inline Approve/Deny prompt in Telegram
- **Two-factor anonymisation** — log data in the database is stored under a hash derived from both a server secret and the user's own passphrase; neither factor alone is enough to identify a user's records

## Privacy model

User data in the database is never stored in plain text. Two separate hashes are used:

| Hash | Formula | Used for |
|---|---|---|
| `approval_hash` | `HMAC(HASH_SECRET, user_id)` | Pending / approved status |
| `data_hash` | `HMAC(HASH_SECRET, user_id:passphrase)` | All log entries |

To link a log entry back to a real person you would need **all three**: the server `HASH_SECRET`, the user's Telegram ID, and their personal passphrase. Timestamps are stored in plain text because they are required for hour calculations.

Passphrases are never written to disk — they are held in process memory for the duration of a session only. If a user forgets their passphrase their past data is permanently inaccessible and future logs start under a new hash.

## Requirements

- Docker and Docker Compose (for deployment)
- Python 3.11+ (for local development)
- A domain name pointing to your server
- Port 443 (and 80 for the ACME challenge) open on your router

## Environment variables

Copy `.env.example` to `.env` and fill in all values.

| Variable | Description |
|---|---|
| `TELEGRAM_BOT_TOKEN` | Token from [@BotFather](https://t.me/BotFather) |
| `HASH_SECRET` | Long random string used as the HMAC key — generate with `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `ADMIN_TELEGRAM_ID` | Your Telegram user ID — get it from [@userinfobot](https://t.me/userinfobot) |
| `WEBHOOK_DOMAIN` | Your domain (e.g. `bot.example.com`). If unset the bot runs in polling mode |

## Deployment (Raspberry Pi / Docker)

```bash
# Clone the repo on your Pi
git clone <repo-url> work-logger-telegram-bot
cd work-logger-telegram-bot

# Configure environment
cp .env.example .env
nano .env

# Start
docker compose up -d

# Follow logs
docker compose logs -f
```

Caddy automatically obtains and renews a TLS certificate from Let's Encrypt on first boot. Make sure ports 443 and 80 are forwarded to your Pi on your router before starting.

The SQLite database is stored in a Docker named volume (`bot_data`) and persists across restarts and container rebuilds.

## Local development (polling mode)

Leave `WEBHOOK_DOMAIN` unset in `.env` and run directly:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 bot.py
```

The bot falls back to long polling automatically when no webhook domain is configured.

## User flow

1. User sends `/start`
2. Bot sends the admin an approval request with **Approve / Deny** buttons
3. Admin taps Approve — user is notified and prompted to set a personal passphrase
4. User sets their passphrase (minimum 4 characters, never stored)
5. The persistent keyboard appears and the user can start logging hours
6. On bot restart the user re-enters their passphrase via `/start` to restore their session

## Project structure

```
bot.py              — all bot logic
Dockerfile          — container image for the bot
docker-compose.yml  — bot + Caddy services
Caddyfile           — reverse proxy config (TLS handled automatically)
requirements.txt    — Python dependencies
.env.example        — environment variable template
```
