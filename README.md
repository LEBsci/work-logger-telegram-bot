# Work Logger Telegram Bot

A Telegram bot for tracking work hours. Users log in and out via a persistent keyboard, request summaries, manage past entries, and set their own timezone.

## Features

- **Log In / Log Out** — one-tap time tracking via a persistent reply keyboard
- **Summary** — breakdown of hours worked today, this week, and this month; counts an open session if currently logged in; displayed in the user's configured timezone
- **Add Entry** — add a past login or logout via an inline calendar, hour grid, and free-text minute input; time is interpreted in the user's timezone
- **Delete Entry** — browse entries by year → month → day and delete individual records with a confirmation step
- **Timezone** — each user sets their own timezone; all displayed times and day/week/month boundaries respect it
- **Admin approval** — new users must be approved before they can use the bot; the admin receives an inline Approve/Deny prompt with a tappable profile link and a copyable user ID
- **Two-factor anonymisation** — log data is stored under a hash derived from both a server secret and the user's own passphrase; neither factor alone is enough to identify a user's records

## Keyboard

```
[ 🟢 Log In ]   [ 🔴 Log Out ]
[       📊 Summary        ]
[ ➕ Add Entry ] [ 🗑 Delete Entry ]
[     🌍 Set Timezone     ]
```

## Admin commands

| Command | Description |
|---|---|
| `/approve <user_id>` | Grant access to a user (works even after a previous denial) |
| `/deny <user_id>` | Revoke access from an approved user |

The user's Telegram ID appears in every approval notification so it can be copied for later use.

## Add Entry flow

1. Tap **➕ Add Entry** → choose **Login** or **Logout**
2. Pick a date from the inline calendar (past dates only)
3. Pick an hour from the grid (00–23)
4. Type the minutes as a number (0–59)
5. Confirm or cancel

All times are entered in the user's configured timezone and stored as UTC.

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
2. Bot notifies the admin — admin taps **Approve** or **Deny**
3. Approved user is prompted to set a personal passphrase (minimum 4 characters, never stored)
4. The persistent keyboard appears; user sets their timezone via **🌍 Set Timezone**
5. User tracks hours with **Log In** / **Log Out**; past entries can be added or deleted at any time
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
