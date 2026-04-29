from __future__ import annotations

import calendar as _cal
import hmac
import hashlib
import html
import logging
import os
import sqlite3
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

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

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

COMMON_TIMEZONES: list[tuple[str, str]] = [
    ("UTC",                              "UTC"),
    ("Europe/London",                    "London"),
    ("Europe/Lisbon",                    "Lisbon"),
    ("Europe/Paris",                     "Madrid / Paris / Berlin"),
    ("Europe/Helsinki",                  "Helsinki / Tallinn"),
    ("Europe/Moscow",                    "Moscow"),
    ("Asia/Dubai",                       "Dubai"),
    ("Asia/Kolkata",                     "India"),
    ("Asia/Bangkok",                     "Bangkok"),
    ("Asia/Singapore",                   "Singapore"),
    ("Asia/Tokyo",                       "Tokyo"),
    ("Australia/Sydney",                 "Sydney"),
    ("Pacific/Auckland",                 "Auckland"),
    ("America/New_York",                 "New York"),
    ("America/Chicago",                  "Chicago"),
    ("America/Denver",                   "Denver"),
    ("America/Los_Angeles",              "Los Angeles"),
    ("America/Sao_Paulo",                "São Paulo"),
    ("America/Argentina/Buenos_Aires",   "Buenos Aires"),
]

KEYBOARD = ReplyKeyboardMarkup(
    [
        [KeyboardButton("🟢 Log In"), KeyboardButton("🔴 Log Out")],
        [KeyboardButton("📊 Summary")],
        [KeyboardButton("➕ Add Entry"), KeyboardButton("🗑 Delete Entry")],
        [KeyboardButton("🌍 Set Timezone")],
    ],
    resize_keyboard=True,
    is_persistent=True,
)


# ── Hashing ───────────────────────────────────────────────────────────────────

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
            CREATE TABLE IF NOT EXISTS user_settings (
                approval_hash TEXT PRIMARY KEY,
                timezone      TEXT NOT NULL DEFAULT 'UTC'
            );
            """
        )


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def is_approved(approval_hash: str) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        return conn.execute(
            "SELECT 1 FROM approved_users WHERE approval_hash = ?", (approval_hash,)
        ).fetchone() is not None


def has_passphrase(approval_hash: str) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT passphrase_set FROM approved_users WHERE approval_hash = ?", (approval_hash,)
        ).fetchone()
    return bool(row and row[0])


def mark_passphrase_set(approval_hash: str) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE approved_users SET passphrase_set = 1 WHERE approval_hash = ?", (approval_hash,)
        )


def is_pending(approval_hash: str) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        return conn.execute(
            "SELECT 1 FROM pending_users WHERE approval_hash = ?", (approval_hash,)
        ).fetchone() is not None


def add_pending(approval_hash: str, user_id: int) -> int:
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            "INSERT OR IGNORE INTO pending_users (approval_hash, user_id, requested_at) VALUES (?, ?, ?)",
            (approval_hash, user_id, _now_utc().isoformat()),
        )
        if cur.lastrowid:
            return cur.lastrowid
        return conn.execute(
            "SELECT id FROM pending_users WHERE approval_hash = ?", (approval_hash,)
        ).fetchone()[0]


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


def revoke_user(approval_hash: str) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM approved_users WHERE approval_hash = ?", (approval_hash,))


def get_user_tz_name(approval_hash: str) -> str:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT timezone FROM user_settings WHERE approval_hash = ?", (approval_hash,)
        ).fetchone()
    return row[0] if row else "UTC"


def set_user_tz(approval_hash: str, tz_name: str) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO user_settings (approval_hash, timezone) VALUES (?, ?) "
            "ON CONFLICT(approval_hash) DO UPDATE SET timezone = excluded.timezone",
            (approval_hash, tz_name),
        )


def _get_tz(approval_hash: str) -> ZoneInfo | timezone:
    name = get_user_tz_name(approval_hash)
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError:
        return timezone.utc


def _insert_log(data_hash: str, action: str, timestamp: datetime | None = None) -> None:
    ts = (timestamp or _now_utc()).isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO logs (data_hash, action, timestamp) VALUES (?, ?, ?)",
            (data_hash, action, ts),
        )


def _last_action(data_hash: str) -> str | None:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT action FROM logs WHERE data_hash = ? ORDER BY timestamp DESC LIMIT 1",
            (data_hash,),
        ).fetchone()
    return row[0] if row else None


def _hours_since(data_hash: str, since: datetime) -> timedelta:
    since_utc = since.astimezone(timezone.utc)
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT action, timestamp FROM logs "
            "WHERE data_hash = ? AND timestamp >= ? ORDER BY timestamp ASC",
            (data_hash, since_utc.isoformat()),
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


# Timestamps stored as ISO strings: "2024-01-15T09:30:00+00:00"
# substr extracts date parts reliably without SQLite strftime timezone issues.

def get_log_years(data_hash: str) -> list[int]:
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT DISTINCT substr(timestamp, 1, 4) FROM logs WHERE data_hash = ? ORDER BY 1 DESC",
            (data_hash,),
        ).fetchall()
    return [int(r[0]) for r in rows]


def get_log_months(data_hash: str, year: int) -> list[int]:
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT DISTINCT substr(timestamp, 6, 2) FROM logs "
            "WHERE data_hash = ? AND substr(timestamp, 1, 4) = ? ORDER BY 1",
            (data_hash, str(year)),
        ).fetchall()
    return [int(r[0]) for r in rows]


def get_log_days(data_hash: str, year: int, month: int) -> list[int]:
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT DISTINCT substr(timestamp, 9, 2) FROM logs "
            "WHERE data_hash = ? AND substr(timestamp, 1, 4) = ? AND substr(timestamp, 6, 2) = ? "
            "ORDER BY 1",
            (data_hash, str(year), f"{month:02d}"),
        ).fetchall()
    return [int(r[0]) for r in rows]


def get_day_entries(data_hash: str, year: int, month: int, day: int) -> list[tuple]:
    with sqlite3.connect(DB_PATH) as conn:
        return conn.execute(
            "SELECT id, action, timestamp FROM logs "
            "WHERE data_hash = ? "
            "AND substr(timestamp, 1, 4) = ? "
            "AND substr(timestamp, 6, 2) = ? "
            "AND substr(timestamp, 9, 2) = ? "
            "ORDER BY timestamp",
            (data_hash, str(year), f"{month:02d}", f"{day:02d}"),
        ).fetchall()


def get_log_entry(entry_id: int, data_hash: str) -> tuple[str, str] | None:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT action, timestamp FROM logs WHERE id = ? AND data_hash = ?",
            (entry_id, data_hash),
        ).fetchone()
    return (row[0], row[1]) if row else None


def delete_log_entry(entry_id: int, data_hash: str) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            "DELETE FROM logs WHERE id = ? AND data_hash = ?", (entry_id, data_hash)
        )
    return cur.rowcount > 0


# ── Inline keyboard builders ──────────────────────────────────────────────────

_NOOP = "cal:_"  # callback_data for non-interactive calendar cells


def _calendar_kbd(year: int, month: int, today: date) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []

    # Month/year header (non-interactive)
    rows.append([InlineKeyboardButton(f"── {MONTHS[month - 1]} {year} ──", callback_data=_NOOP)])

    # Weekday headers
    rows.append([InlineKeyboardButton(d, callback_data=_NOOP) for d in ["Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"]])

    # Day grid
    for week in _cal.monthcalendar(year, month):
        row = []
        for day in week:
            if day == 0:
                row.append(InlineKeyboardButton(" ", callback_data=_NOOP))
            elif date(year, month, day) > today:
                row.append(InlineKeyboardButton("·", callback_data=_NOOP))
            else:
                row.append(InlineKeyboardButton(str(day), callback_data=f"cal:d:{year}{month:02d}{day:02d}"))
        rows.append(row)

    # Navigation
    py, pm = (year, month - 1) if month > 1 else (year - 1, 12)
    ny, nm = (year, month + 1) if month < 12 else (year + 1, 1)
    nav = [InlineKeyboardButton("◀", callback_data=f"cal:p:{py}{pm:02d}")]
    nav.append(InlineKeyboardButton("❌", callback_data="cal:x"))
    if (ny, nm) <= (today.year, today.month):
        nav.append(InlineKeyboardButton("▶", callback_data=f"cal:n:{ny}{nm:02d}"))
    else:
        nav.append(InlineKeyboardButton("·", callback_data=_NOOP))
    rows.append(nav)

    return InlineKeyboardMarkup(rows)


def _hour_kbd(ymd: str) -> InlineKeyboardMarkup:
    rows = []
    for start in range(0, 24, 6):
        rows.append([
            InlineKeyboardButton(f"{h:02d}", callback_data=f"th:{ymd}{h:02d}")
            for h in range(start, start + 6)
        ])
    rows.append([InlineKeyboardButton("❌ Cancel", callback_data="tcan")])
    return InlineKeyboardMarkup(rows)


def _cancel_kbd() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="tcan")]])


def _timezone_kbd() -> InlineKeyboardMarkup:
    rows = [[InlineKeyboardButton(label, callback_data=f"tz:{name}")] for name, label in COMMON_TIMEZONES]
    rows.append([InlineKeyboardButton("❌ Cancel", callback_data="tz:x")])
    return InlineKeyboardMarkup(rows)


def _approval_kbd(pending_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[
        InlineKeyboardButton("✅ Approve", callback_data=f"approve:{pending_id}"),
        InlineKeyboardButton("❌ Deny",    callback_data=f"deny:{pending_id}"),
    ]])


def _mention_html(user) -> str:
    name = user.full_name or user.first_name or "Unknown"
    label = f"{name} (@{user.username})" if user.username else name
    return f'<a href="tg://user?id={user.id}">{html.escape(label)}</a>'


# ── Session helpers ───────────────────────────────────────────────────────────

async def _get_session_hash(update: Update, context: ContextTypes.DEFAULT_TYPE) -> str | None:
    user = update.effective_user
    if user.id == ADMIN_ID:
        return _data_hash(ADMIN_ID, "__admin__")
    passphrase = context.user_data.get("passphrase")
    if not passphrase:
        msg = "🔐 Session expired. Send /start to re-enter your passphrase."
        if update.callback_query:
            await update.callback_query.answer(msg, show_alert=True)
        else:
            await update.message.reply_text(msg)
        return None
    return _data_hash(user.id, passphrase)


def _delete_entry_start_kbd(data_hash: str) -> tuple[str, InlineKeyboardMarkup] | None:
    """Return (text, keyboard) for the first level of delete navigation, skipping single-choice levels."""
    years = get_log_years(data_hash)
    if not years:
        return None
    if len(years) == 1:
        months = get_log_months(data_hash, years[0])
        if len(months) == 1:
            days = get_log_days(data_hash, years[0], months[0])
            return (
                f"Select a day in {MONTHS[months[0] - 1]} {years[0]}:",
                _day_kbd(years[0], months[0], days),
            )
        return (f"Select a month in {years[0]}:", _month_kbd(years[0], months))
    return ("Select a year:", _year_kbd(years))


def _year_kbd(years: list[int]) -> InlineKeyboardMarkup:
    rows = [[InlineKeyboardButton(str(y), callback_data=f"dl_y:{y}")] for y in years]
    rows.append([InlineKeyboardButton("❌ Cancel", callback_data="dl_x")])
    return InlineKeyboardMarkup(rows)


def _month_kbd(year: int, months: list[int]) -> InlineKeyboardMarkup:
    rows = [[InlineKeyboardButton(MONTHS[m - 1], callback_data=f"dl_m:{year}{m:02d}")] for m in months]
    rows.append([InlineKeyboardButton("❌ Cancel", callback_data="dl_x")])
    return InlineKeyboardMarkup(rows)


def _day_kbd(year: int, month: int, days: list[int]) -> InlineKeyboardMarkup:
    rows, row = [], []
    for d in days:
        row.append(InlineKeyboardButton(str(d), callback_data=f"dl_d:{year}{month:02d}{d:02d}"))
        if len(row) == 5:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    rows.append([InlineKeyboardButton("❌ Cancel", callback_data="dl_x")])
    return InlineKeyboardMarkup(rows)


def _entry_kbd(entries: list[tuple], tz: ZoneInfo | timezone) -> InlineKeyboardMarkup:
    rows = []
    for entry_id, action, ts_str in entries:
        ts = datetime.fromisoformat(ts_str).astimezone(tz)
        icon = "🟢" if action == "login" else "🔴"
        rows.append([InlineKeyboardButton(
            f"{icon} {ts.strftime('%H:%M')}",
            callback_data=f"dl_e:{entry_id}",
        )])
    rows.append([InlineKeyboardButton("❌ Cancel", callback_data="dl_x")])
    return InlineKeyboardMarkup(rows)


def _confirm_delete_kbd(entry_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[
        InlineKeyboardButton("🗑 Delete", callback_data=f"dl_ok:{entry_id}"),
        InlineKeyboardButton("❌ Cancel", callback_data="dl_x"),
    ]])


# ── Handlers ──────────────────────────────────────────────────────────────────

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user

    if user.id == ADMIN_ID:
        await update.message.reply_text("👋 Welcome, Admin! Work Logger is running.", reply_markup=KEYBOARD)
        return

    approval_hash = _approval_hash(user.id)

    if not is_approved(approval_hash):
        if is_pending(approval_hash):
            await update.message.reply_text("⏳ Your access request is pending admin approval.")
            return
        pending_id = add_pending(approval_hash, user.id)
        await context.bot.send_message(
            chat_id=ADMIN_ID,
            text=(
                f"🔔 <b>New access request</b>\n\n"
                f"{_mention_html(user)} wants to use the Work Logger bot.\n"
                f"<code>ID: {user.id}</code>"
            ),
            parse_mode="HTML",
            reply_markup=_approval_kbd(pending_id),
        )
        await update.message.reply_text("📨 Access request sent to the admin. You'll be notified once approved.")
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
        await context.bot.send_message(user_id, "✅ Your access has been approved! Send /start to set up your passphrase.")
    elif action == "deny":
        deny_user(approval_hash)
        await query.edit_message_text("❌ User denied.")
        await context.bot.send_message(user_id, "❌ Your access request was denied.")


async def cmd_admin_approve(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_user.id != ADMIN_ID:
        return
    if not context.args:
        await update.message.reply_text("Usage: /approve <user_id>")
        return
    try:
        target_id = int(context.args[0])
    except ValueError:
        await update.message.reply_text("Invalid user ID — must be a number.")
        return
    ah = _approval_hash(target_id)
    if is_approved(ah):
        await update.message.reply_text("User is already approved.")
        return
    approve_user(ah)
    await update.message.reply_text(f"✅ User {target_id} approved.")
    try:
        await context.bot.send_message(target_id, "✅ Your access has been approved! Send /start to continue.")
    except Exception:
        await update.message.reply_text("(Could not notify the user — they may not have started the bot yet.)")


async def cmd_admin_deny(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_user.id != ADMIN_ID:
        return
    if not context.args:
        await update.message.reply_text("Usage: /deny <user_id>")
        return
    try:
        target_id = int(context.args[0])
    except ValueError:
        await update.message.reply_text("Invalid user ID — must be a number.")
        return
    ah = _approval_hash(target_id)
    if not is_approved(ah):
        await update.message.reply_text("User is not currently approved.")
        return
    revoke_user(ah)
    await update.message.reply_text(f"❌ User {target_id} access revoked.")
    try:
        await context.bot.send_message(target_id, "❌ Your access has been revoked by the admin.")
    except Exception:
        pass


async def handle_delete_nav(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()

    if query.data == "dl_x":
        await query.edit_message_text("Cancelled.")
        return

    data_hash = await _get_session_hash(update, context)
    if data_hash is None:
        return

    tz = _get_tz(_approval_hash(update.effective_user.id))
    cmd = query.data

    if cmd.startswith("dl_y:"):
        year = int(cmd[5:])
        months = get_log_months(data_hash, year)
        await query.edit_message_text(f"Select a month in {year}:", reply_markup=_month_kbd(year, months))

    elif cmd.startswith("dl_m:"):
        ym = cmd[5:]
        year, month = int(ym[:4]), int(ym[4:])
        days = get_log_days(data_hash, year, month)
        await query.edit_message_text(
            f"Select a day in {MONTHS[month - 1]} {year}:",
            reply_markup=_day_kbd(year, month, days),
        )

    elif cmd.startswith("dl_d:"):
        ymd = cmd[5:]
        year, month, day = int(ymd[:4]), int(ymd[4:6]), int(ymd[6:])
        entries = get_day_entries(data_hash, year, month, day)
        await query.edit_message_text(
            f"Select an entry to delete ({day} {MONTHS[month - 1]} {year}):",
            reply_markup=_entry_kbd(entries, tz),
        )

    elif cmd.startswith("dl_e:"):
        entry_id = int(cmd[5:])
        entry = get_log_entry(entry_id, data_hash)
        if not entry:
            await query.edit_message_text("Entry not found.")
            return
        action, ts_str = entry
        ts = datetime.fromisoformat(ts_str).astimezone(tz)
        icon = "🟢 Login" if action == "login" else "🔴 Logout"
        tz_name = get_user_tz_name(_approval_hash(update.effective_user.id))
        await query.edit_message_text(
            f"Delete this entry?\n\n{icon} — {ts.strftime('%d %b %Y at %H:%M')} ({tz_name})",
            reply_markup=_confirm_delete_kbd(entry_id),
        )

    elif cmd.startswith("dl_ok:"):
        entry_id = int(cmd[6:])
        if delete_log_entry(entry_id, data_hash):
            await query.edit_message_text("✅ Entry deleted.")
        else:
            await query.edit_message_text("Entry not found or already deleted.")


async def handle_add_entry(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    cmd = query.data

    if cmd == "add_x":
        context.user_data.pop("add_action", None)
        context.user_data.pop("add_ts", None)
        await query.edit_message_text("Cancelled.")
        return

    if cmd in ("add_in", "add_out"):
        context.user_data["add_action"] = "login" if cmd == "add_in" else "logout"
        ah = _approval_hash(update.effective_user.id)
        tz = _get_tz(ah)
        today = _now_utc().astimezone(tz).date()
        await query.edit_message_text(
            "Select a date:",
            reply_markup=_calendar_kbd(today.year, today.month, today),
        )

    elif cmd == "add_confirm":
        data_hash = await _get_session_hash(update, context)
        if data_hash is None:
            return
        action = context.user_data.pop("add_action", None)
        ts: datetime | None = context.user_data.pop("add_ts", None)
        if action and ts:
            _insert_log(data_hash, action, ts)
            await query.edit_message_text("✅ Entry added.")
        else:
            await query.edit_message_text("Something went wrong — please try again.")


async def handle_calendar(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    cmd = query.data

    if cmd in ("cal:x", "cal:_"):
        if cmd == "cal:x":
            context.user_data.pop("add_action", None)
            await query.edit_message_text("Cancelled.")
        return

    ah = _approval_hash(update.effective_user.id)
    tz = _get_tz(ah)
    today = _now_utc().astimezone(tz).date()

    if cmd.startswith("cal:p:") or cmd.startswith("cal:n:"):
        ym = cmd[6:]
        year, month = int(ym[:4]), int(ym[4:])
        await query.edit_message_text(
            "Select a date:",
            reply_markup=_calendar_kbd(year, month, today),
        )

    elif cmd.startswith("cal:d:"):
        ymd = cmd[6:]
        await query.edit_message_text(
            f"Select an hour ({ymd[:4]}-{ymd[4:6]}-{ymd[6:]}):",
            reply_markup=_hour_kbd(ymd),
        )


async def handle_time_pick(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    cmd = query.data

    if cmd == "tcan":
        context.user_data.pop("add_action", None)
        context.user_data.pop("add_ts", None)
        context.user_data.pop("add_ymdh", None)
        context.user_data.pop("state", None)
        await query.edit_message_text("Cancelled.")
        return

    if cmd.startswith("th:"):
        ymdh = cmd[3:]
        ymd = ymdh[:8]
        hour = int(ymdh[8:])
        context.user_data["add_ymdh"] = ymdh
        context.user_data["state"] = "add_minutes"
        await query.edit_message_text(
            f"*{ymd[:4]}-{ymd[4:6]}-{ymd[6:]} at {hour:02d}:__*\n\nType the minutes (0–59):",
            parse_mode="Markdown",
            reply_markup=_cancel_kbd(),
        )


async def handle_timezone(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    cmd = query.data

    if cmd == "tz:x":
        await query.edit_message_text("Timezone unchanged.")
        return

    tz_name = cmd[3:]
    try:
        ZoneInfo(tz_name)
    except ZoneInfoNotFoundError:
        await query.edit_message_text("Unknown timezone.")
        return

    ah = _approval_hash(update.effective_user.id)
    set_user_tz(ah, tz_name)
    await query.edit_message_text(f"✅ Timezone set to *{tz_name}*.", parse_mode="Markdown")


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    text = update.message.text
    state = context.user_data.get("state")

    if state == "add_minutes":
        try:
            minute = int(text.strip())
            if not 0 <= minute <= 59:
                raise ValueError
        except ValueError:
            await update.message.reply_text("⚠️ Enter a whole number between 0 and 59.")
            return
        ymdh = context.user_data.pop("add_ymdh", None)
        context.user_data.pop("state", None)
        if not ymdh:
            await update.message.reply_text("Something went wrong — please start over.")
            return
        year, month, day, hour = int(ymdh[:4]), int(ymdh[4:6]), int(ymdh[6:8]), int(ymdh[8:])
        ah = _approval_hash(user.id)
        tz = _get_tz(ah)
        tz_name = get_user_tz_name(ah)
        local_dt = datetime(year, month, day, hour, minute, tzinfo=tz)
        if local_dt.astimezone(timezone.utc) > _now_utc():
            await update.message.reply_text("⚠️ Can't add entries in the future.")
            return
        context.user_data["add_ts"] = local_dt.astimezone(timezone.utc)
        action = context.user_data.get("add_action", "login")
        icon = "🟢 Login" if action == "login" else "🔴 Logout"
        await update.message.reply_text(
            f"Add this entry?\n\n{icon} — {local_dt.strftime('%d %b %Y at %H:%M')} ({tz_name})",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("✅ Confirm", callback_data="add_confirm"),
                InlineKeyboardButton("❌ Cancel",  callback_data="add_x"),
            ]]),
        )
        return

    if user.id == ADMIN_ID:
        await _handle_work_buttons(update, _data_hash(ADMIN_ID, "__admin__"))
        return

    approval_hash = _approval_hash(user.id)

    if not is_approved(approval_hash):
        await update.message.reply_text("🚫 You don't have access yet. Send /start to request it.")
        return

    if state == "setup_passphrase":
        if len(text.strip()) < 4:
            await update.message.reply_text("⚠️ Too short. Please use at least 4 characters.")
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
        await update.message.reply_text("🔐 Session expired. Send /start to re-enter your passphrase.")
        return

    await _handle_work_buttons(update, _data_hash(user.id, passphrase))


async def _handle_work_buttons(update: Update, data_hash: str) -> None:
    text = update.message.text
    user = update.effective_user
    ah = _approval_hash(user.id)
    tz = _get_tz(ah)
    tz_name = get_user_tz_name(ah)

    if text == "🟢 Log In":
        if _last_action(data_hash) == "login":
            await update.message.reply_text("You're already logged in.")
            return
        _insert_log(data_hash, "login")
        now_local = _now_utc().astimezone(tz)
        await update.message.reply_text(f"✅ Logged in at {now_local.strftime('%H:%M')} ({tz_name})")

    elif text == "🔴 Log Out":
        if _last_action(data_hash) != "login":
            await update.message.reply_text("You're not currently logged in.")
            return
        _insert_log(data_hash, "logout")
        now_local = _now_utc().astimezone(tz)
        await update.message.reply_text(f"👋 Logged out at {now_local.strftime('%H:%M')} ({tz_name})")

    elif text == "📊 Summary":
        now_local = _now_utc().astimezone(tz)
        today_start = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = today_start - timedelta(days=now_local.weekday())
        month_start = today_start.replace(day=1)
        await update.message.reply_text(
            f"📊 *Work Summary* ({tz_name})\n\n"
            f"Today:      {_fmt_duration(_hours_since(data_hash, today_start))}\n"
            f"This week:  {_fmt_duration(_hours_since(data_hash, week_start))}\n"
            f"This month: {_fmt_duration(_hours_since(data_hash, month_start))}",
            parse_mode="Markdown",
        )

    elif text == "➕ Add Entry":
        await update.message.reply_text(
            "What type of entry?",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🟢 Login",  callback_data="add_in"),
                InlineKeyboardButton("🔴 Logout", callback_data="add_out"),
                InlineKeyboardButton("❌ Cancel", callback_data="add_x"),
            ]]),
        )

    elif text == "🗑 Delete Entry":
        result = _delete_entry_start_kbd(data_hash)
        if result is None:
            await update.message.reply_text("No log entries found.")
            return
        label, kbd = result
        await update.message.reply_text(label, reply_markup=kbd)

    elif text == "🌍 Set Timezone":
        current = get_user_tz_name(ah)
        await update.message.reply_text(
            f"Current timezone: *{current}*\n\nSelect a new timezone:",
            parse_mode="Markdown",
            reply_markup=_timezone_kbd(),
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
    app.add_handler(CommandHandler("start",   cmd_start))
    app.add_handler(CommandHandler("approve", cmd_admin_approve))
    app.add_handler(CommandHandler("deny",    cmd_admin_deny))
    app.add_handler(CallbackQueryHandler(handle_approval,   pattern=r"^(approve|deny):"))
    app.add_handler(CallbackQueryHandler(handle_delete_nav, pattern=r"^dl_"))
    app.add_handler(CallbackQueryHandler(handle_add_entry,  pattern=r"^add_"))
    app.add_handler(CallbackQueryHandler(handle_calendar,   pattern=r"^cal:"))
    app.add_handler(CallbackQueryHandler(handle_time_pick,  pattern=r"^(th:|tcan)"))
    app.add_handler(CallbackQueryHandler(handle_timezone,   pattern=r"^tz:"))
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
