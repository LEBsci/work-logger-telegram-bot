from __future__ import annotations

import hmac
import hashlib
import logging
import os
import sqlite3
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from telegram import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    KeyboardButton,
    ReplyKeyboardMarkup,
    Update,
)
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

load_dotenv()

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)

ADMIN_ID: int = int(os.environ["ADMIN_TELEGRAM_ID"])
DB_PATH: str = os.environ.get("DB_PATH", "work_logs.db")

KEYBOARD = ReplyKeyboardMarkup(
    [
        [KeyboardButton("🟢 Log In"), KeyboardButton("🔴 Log Out")],
        [KeyboardButton("📊 Summary")],
    ],
    resize_keyboard=True,
    is_persistent=True,
)


# ── Hashing ───────────────────────────────────────────────────────────────────
# Two separate hashes keep approval tracking and log data unlinkable:
#
#   approval_hash = HMAC(HASH_SECRET, user_id)
#     → used only to check pending/approved status
#     → admin + user_id is enough to compute it (membership check only)
#
#   data_hash = HMAC(HASH_SECRET, "user_id:passphrase")
#     → used for every log entry
#     → requires HASH_SECRET *and* the user's personal passphrase to reverse
#     → admin cannot link a data_hash to a real user without the passphrase

def _approval_hash(user_id: int) -> str:
    key = os.environ["HASH_SECRET"].encode()
    return hmac.new(key, str(user_id).encode(), hashlib.sha256).hexdigest()


def _data_hash(user_id: int, passphrase: str) -> str:
    key = os.environ["HASH_SECRET"].encode()
    return hmac.new(key, f"{user_id}:{passphrase}".encode(), hashlib.sha256).hexdigest()


# ── Database ──────────────────────────────────────────────────────────────────

def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS approved_users (
                approval_hash  TEXT PRIMARY KEY,
                approved_at    TEXT NOT NULL,
                passphrase_set INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS pending_users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                approval_hash TEXT UNIQUE NOT NULL,
                user_id       INTEGER NOT NULL,
                requested_at  TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS logs (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                data_hash TEXT NOT NULL,
                action    TEXT NOT NULL CHECK(action IN ('login', 'logout')),
                timestamp TEXT NOT NULL
            );
            """
        )


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def is_approved(approval_hash: str) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        return (
            conn.execute(
                "SELECT 1 FROM approved_users WHERE approval_hash = ?", (approval_hash,)
            ).fetchone()
            is not None
        )


def has_passphrase(approval_hash: str) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT passphrase_set FROM approved_users WHERE approval_hash = ?",
            (approval_hash,),
        ).fetchone()
    return bool(row and row[0])


def mark_passphrase_set(approval_hash: str) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE approved_users SET passphrase_set = 1 WHERE approval_hash = ?",
            (approval_hash,),
        )


def is_pending(approval_hash: str) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        return (
            conn.execute(
                "SELECT 1 FROM pending_users WHERE approval_hash = ?", (approval_hash,)
            ).fetchone()
            is not None
        )


def add_pending(approval_hash: str, user_id: int) -> int:
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            "INSERT OR IGNORE INTO pending_users (approval_hash, user_id, requested_at) VALUES (?, ?, ?)",
            (approval_hash, user_id, _now_utc().isoformat()),
        )
        if cur.lastrowid:
            return cur.lastrowid
        row = conn.execute(
            "SELECT id FROM pending_users WHERE approval_hash = ?", (approval_hash,)
        ).fetchone()
        return row[0]


def get_pending(pending_id: int) -> tuple[str, int] | None:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT approval_hash, user_id FROM pending_users WHERE id = ?", (pending_id,)
        ).fetchone()
    return (row[0], row[1]) if row else None


def approve_user(approval_hash: str) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM pending_users WHERE approval_hash = ?", (approval_hash,))
        conn.execute(
            "INSERT OR IGNORE INTO approved_users (approval_hash, approved_at) VALUES (?, ?)",
            (approval_hash, _now_utc().isoformat()),
        )


def deny_user(approval_hash: str) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM pending_users WHERE approval_hash = ?", (approval_hash,))


def _insert_log(data_hash: str, action: str) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO logs (data_hash, action, timestamp) VALUES (?, ?, ?)",
            (data_hash, action, _now_utc().isoformat()),
        )


def _last_action(data_hash: str) -> str | None:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT action FROM logs WHERE data_hash = ? ORDER BY timestamp DESC LIMIT 1",
            (data_hash,),
        ).fetchone()
    return row[0] if row else None


def _hours_since(data_hash: str, since: datetime) -> timedelta:
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT action, timestamp FROM logs "
            "WHERE data_hash = ? AND timestamp >= ? ORDER BY timestamp ASC",
            (data_hash, since.isoformat()),
        ).fetchall()

    total = timedelta()
    login_time: datetime | None = None

    for action, ts_str in rows:
        ts = datetime.fromisoformat(ts_str)
        if action == "login":
            login_time = ts
        elif action == "logout" and login_time is not None:
            total += ts - login_time
            login_time = None

    if login_time is not None:
        total += _now_utc() - login_time

    return total


def _fmt_duration(td: timedelta) -> str:
    total_mins = int(td.total_seconds() // 60)
    h, m = divmod(total_mins, 60)
    return f"{h}h {m:02d}m"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _approval_keyboard(pending_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("✅ Approve", callback_data=f"approve:{pending_id}"),
                InlineKeyboardButton("❌ Deny",    callback_data=f"deny:{pending_id}"),
            ]
        ]
    )


def _display_name(user) -> str:
    name = user.full_name or user.first_name or "Unknown"
    return f"{name} (@{user.username})" if user.username else name


# ── Handlers ──────────────────────────────────────────────────────────────────

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user

    if user.id == ADMIN_ID:
        await update.message.reply_text(
            "👋 Welcome, Admin! Work Logger is running.",
            reply_markup=KEYBOARD,
        )
        return

    approval_hash = _approval_hash(user.id)

    if not is_approved(approval_hash):
        if is_pending(approval_hash):
            await update.message.reply_text("⏳ Your access request is pending admin approval.")
            return
        pending_id = add_pending(approval_hash, user.id)
        await context.bot.send_message(
            chat_id=ADMIN_ID,
            text=f"🔔 *New access request*\n\n{_display_name(user)} wants to use the Work Logger bot.",
            parse_mode="Markdown",
            reply_markup=_approval_keyboard(pending_id),
        )
        await update.message.reply_text(
            "📨 Access request sent to the admin. You'll be notified once approved."
        )
        return

    if not has_passphrase(approval_hash):
        context.user_data["state"] = "setup_passphrase"
        await update.message.reply_text(
            "🔐 *Set your secret passphrase*\n\n"
            "Choose any word or phrase that only you know. "
            "It's combined with a server secret to protect your data — "
            "without it, even the admin cannot read your logs.\n\n"
            "⚠️ If you forget it, your history cannot be recovered.\n\n"
            "Send your passphrase now:",
            parse_mode="Markdown",
        )
        return

    context.user_data["state"] = "login_passphrase"
    await update.message.reply_text("🔐 Enter your passphrase to resume your session:")


async def handle_approval(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query

    if update.effective_user.id != ADMIN_ID:
        await query.answer("Not authorised.", show_alert=True)
        return

    await query.answer()
    action, pending_id_str = query.data.split(":", 1)
    pending = get_pending(int(pending_id_str))

    if pending is None:
        await query.edit_message_text("⚠️ Request no longer pending.")
        return

    approval_hash, user_id = pending

    if action == "approve":
        approve_user(approval_hash)
        await query.edit_message_text("✅ User approved.")
        await context.bot.send_message(
            chat_id=user_id,
            text="✅ Your access has been approved! Send /start to set up your passphrase.",
        )
    elif action == "deny":
        deny_user(approval_hash)
        await query.edit_message_text("❌ User denied.")
        await context.bot.send_message(
            chat_id=user_id,
            text="❌ Your access request was denied.",
        )


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    text = update.message.text
    state = context.user_data.get("state")

    if user.id == ADMIN_ID:
        await _handle_work_buttons(update, _data_hash(ADMIN_ID, "__admin__"))
        return

    approval_hash = _approval_hash(user.id)

    if not is_approved(approval_hash):
        await update.message.reply_text(
            "🚫 You don't have access yet. Send /start to request it."
        )
        return

    if state == "setup_passphrase":
        if len(text.strip()) < 4:
            await update.message.reply_text(
                "⚠️ Too short. Please use at least 4 characters."
            )
            return
        context.user_data["passphrase"] = text.strip()
        context.user_data.pop("state", None)
        mark_passphrase_set(approval_hash)
        await update.message.reply_text(
            "✅ Passphrase set! Your logs are now protected.\n"
            "Remember it — there's no way to recover it if lost.",
            reply_markup=KEYBOARD,
        )
        return

    if state == "login_passphrase":
        context.user_data["passphrase"] = text.strip()
        context.user_data.pop("state", None)
        await update.message.reply_text("✅ Session restored.", reply_markup=KEYBOARD)
        return

    passphrase = context.user_data.get("passphrase")
    if not passphrase:
        await update.message.reply_text(
            "🔐 Session expired. Send /start to re-enter your passphrase."
        )
        return

    await _handle_work_buttons(update, _data_hash(user.id, passphrase))


async def _handle_work_buttons(update: Update, data_hash: str) -> None:
    text = update.message.text

    if text == "🟢 Log In":
        if _last_action(data_hash) == "login":
            await update.message.reply_text("You're already logged in.")
            return
        _insert_log(data_hash, "login")
        await update.message.reply_text(f"✅ Logged in at {_now_utc().strftime('%H:%M UTC')}")

    elif text == "🔴 Log Out":
        if _last_action(data_hash) != "login":
            await update.message.reply_text("You're not currently logged in.")
            return
        _insert_log(data_hash, "logout")
        await update.message.reply_text(f"👋 Logged out at {_now_utc().strftime('%H:%M UTC')}")

    elif text == "📊 Summary":
        now = _now_utc()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = today_start - timedelta(days=now.weekday())
        month_start = today_start.replace(day=1)

        await update.message.reply_text(
            "📊 *Work Summary*\n\n"
            f"Today:      {_fmt_duration(_hours_since(data_hash, today_start))}\n"
            f"This week:  {_fmt_duration(_hours_since(data_hash, week_start))}\n"
            f"This month: {_fmt_duration(_hours_since(data_hash, month_start))}",
            parse_mode="Markdown",
        )


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        raise RuntimeError("Set TELEGRAM_BOT_TOKEN in your .env file.")
    if not os.environ.get("HASH_SECRET"):
        raise RuntimeError("Set HASH_SECRET in your .env file.")
    if not os.environ.get("ADMIN_TELEGRAM_ID"):
        raise RuntimeError("Set ADMIN_TELEGRAM_ID in your .env file.")

    webhook_domain = os.environ.get("WEBHOOK_DOMAIN")

    init_db()

    app = Application.builder().token(token).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CallbackQueryHandler(handle_approval, pattern=r"^(approve|deny):"))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    if webhook_domain:
        logging.info("Bot started — webhook mode on %s", webhook_domain)
        app.run_webhook(
            listen="0.0.0.0",
            port=8000,
            url_path=token,
            webhook_url=f"https://{webhook_domain}/{token}",
            drop_pending_updates=True,
        )
    else:
        logging.info("Bot started — polling mode")
        app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
