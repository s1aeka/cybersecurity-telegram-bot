import asyncio
import csv
import html
import ipaddress
import io
import logging
import os
import re
import secrets
import socket
import string
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator
from urllib.parse import quote, urlsplit

import aiohttp
import aiomysql
from ai_analyst import generate_ai_report
from aiogram import Bot, Dispatcher, F
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import (
    BufferedInputFile,
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    KeyboardButton,
    Message,
    ReplyKeyboardMarkup,
)
from archive_scanner import run_asset_discovery
from openai import APIError


# Configure these values with environment variables; never commit real credentials.
BOT_TOKEN = os.getenv("BOT_TOKEN", "YOUR_BOT_TOKEN_HERE")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "YOUR_MYSQL_PASSWORD_HERE")
ADMIN_ID = int(os.getenv("ADMIN_ID", "0"))
MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_USER = os.getenv("MYSQL_USER", "root")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "tg_bot_db")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

dp = Dispatcher()
db_pool: aiomysql.Pool | None = None

IP_DOMAIN_LOOKUP = "🔍 IP / Domain Lookup"
HEADER_ANALYSIS = "🛡️ Analyze HTTP Headers"
EMAIL_LEAK_CHECK = "📧 Check Email Leaks"
GENERATE_PASSWORD = "🔐 Generate Password"
DEFEND_PATCH = "🛡️ Defend & Patch Config"
ASSET_DISCOVERY = "🕵️ Asset & Archive Discovery"
CRYPTO_RADAR = "🚨 Crypto & Leak Radar"
ATTACK_SIMULATOR = "🤖 Attack Path Simulator"
MY_STATS = "📊 My Stats & History"
HELP = "ℹ️ Help"

main_keyboard = ReplyKeyboardMarkup(
    keyboard=[
        [KeyboardButton(text=DEFEND_PATCH)],
        [KeyboardButton(text=ASSET_DISCOVERY)],
        [KeyboardButton(text=CRYPTO_RADAR)],
        [KeyboardButton(text=ATTACK_SIMULATOR)],
        [KeyboardButton(text=MY_STATS), KeyboardButton(text=HELP)],
    ],
    resize_keyboard=True,
    is_persistent=True,
)
history_keyboard = InlineKeyboardMarkup(
    inline_keyboard=[
        [
            InlineKeyboardButton(
                text="📥 Export History (CSV)", callback_data="export_history"
            )
        ]
    ]
)

SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
)
EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


class SearchStates(StatesGroup):
    waiting_for_ip_domain = State()
    waiting_for_url = State()
    waiting_for_email = State()
    waiting_for_patch_context = State()
    waiting_for_asset_domain = State()
    waiting_for_crypto_input = State()
    waiting_for_attack_context = State()


class UnsafeTargetError(ValueError):
    """Raised when a requested URL resolves to a non-public network address."""


class PublicResolver(aiohttp.abc.AbstractResolver):
    """Prevent user-supplied URLs from reaching private or local network hosts."""

    def __init__(self) -> None:
        self._resolver = aiohttp.resolver.DefaultResolver()

    async def resolve(
        self, host: str, port: int = 0, family: int = socket.AF_UNSPEC
    ) -> list[dict[str, Any]]:
        records = await self._resolver.resolve(host, port, family)
        for record in records:
            address = ipaddress.ip_address(record["host"])
            if not address.is_global:
                raise UnsafeTargetError("Only publicly routable hosts can be scanned.")
        return records

    async def close(self) -> None:
        await self._resolver.close()


def quote_identifier(identifier: str) -> str:
    """Safely escape a database name for SQL."""
    return f"`{identifier.replace('`', '``')}`"


@asynccontextmanager
async def acquire_db_connection() -> AsyncGenerator[aiomysql.Connection, None]:
    if db_pool is None:
        raise RuntimeError("The database connection has not been initialized.")

    async with db_pool.acquire() as connection:
        # Ask aiomysql to reconnect a stale pooled connection before using it.
        await connection.ping(reconnect=True)
        yield connection


async def initialize_database() -> aiomysql.Pool:
    """Create required tables and return the MySQL connection pool."""
    database_name = quote_identifier(MYSQL_DATABASE)
    connection = await aiomysql.connect(
        host=MYSQL_HOST,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        charset="utf8mb4",
        autocommit=True,
    )
    try:
        async with connection.cursor() as cursor:
            await cursor.execute(
                f"CREATE DATABASE IF NOT EXISTS {database_name} "
                "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
    finally:
        connection.close()

    pool = await aiomysql.create_pool(
        host=MYSQL_HOST,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        db=MYSQL_DATABASE,
        charset="utf8mb4",
        autocommit=True,
        minsize=1,
        maxsize=10,
        pool_recycle=1800,
    )
    try:
        async with pool.acquire() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        telegram_id BIGINT NOT NULL UNIQUE,
                        username VARCHAR(255),
                        first_name VARCHAR(255),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                    """
                )
                await cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS search_history (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        telegram_id BIGINT NOT NULL,
                        search_type VARCHAR(50),
                        query_data TEXT,
                        result_data TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                    """
                )
    except Exception:
        pool.close()
        await pool.wait_closed()
        raise

    return pool


async def save_search_history(
    telegram_id: int, search_type: str, query_data: str, result_data: str
) -> None:
    async with acquire_db_connection() as connection:
        async with connection.cursor() as cursor:
            await cursor.execute(
                """
                INSERT INTO search_history
                    (telegram_id, search_type, query_data, result_data)
                VALUES (%s, %s, %s, %s)
                """,
                (telegram_id, search_type, query_data, result_data),
            )


async def record_history(
    message: Message, search_type: str, query_data: str, result_data: str
) -> bool:
    if message.from_user is None:
        return False
    try:
        await save_search_history(
            message.from_user.id, search_type, query_data, result_data
        )
    except (aiomysql.MySQLError, RuntimeError):
        logger.exception(
            "Could not save %s history for user %s",
            search_type,
            message.from_user.id,
        )
        return False
    return True


def validate_lookup_target(query: str) -> str | None:
    try:
        return str(ipaddress.ip_address(query))
    except ValueError:
        pass

    domain = query.rstrip(".")
    try:
        ascii_domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(ascii_domain) > 253 or "." not in ascii_domain:
        return None
    labels = ascii_domain.split(".")
    if all(label.isdigit() for label in labels):
        return None
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in labels
    ):
        return None
    return ascii_domain


def is_valid_email(email: str) -> bool:
    if len(email) > 254 or EMAIL_PATTERN.fullmatch(email) is None:
        return False
    local_part = email.rsplit("@", 1)[0]
    return (
        len(local_part) <= 64
        and not local_part.startswith(".")
        and not local_part.endswith(".")
        and ".." not in local_part
    )


def generate_secure_password() -> str:
    groups = (
        string.ascii_uppercase,
        string.ascii_lowercase,
        string.digits,
        "!@#$%^&*",
    )
    characters = [secrets.choice(group) for group in groups]
    alphabet = "".join(groups)
    characters.extend(secrets.choice(alphabet) for _ in range(12))
    secrets.SystemRandom().shuffle(characters)
    return "".join(characters)


def format_header_scan(headers: aiohttp.typedefs.LooseHeaders) -> str:
    present = {name.lower(): value for name, value in headers.items()}
    detected = sum(header.lower() in present for header in SECURITY_HEADERS)
    grade = {4: "A", 3: "B", 2: "C", 1: "D", 0: "F"}[detected]
    lines = [f"Security grade: <b>{grade}</b> ({detected}/4 headers detected)"]
    for header in SECURITY_HEADERS:
        value = present.get(header.lower())
        if value:
            lines.append(f"✅ <b>{html.escape(header)}:</b> <code>{html.escape(str(value))}</code>")
        else:
            lines.append(f"❌ <b>{html.escape(header)}:</b> Missing")
    return "\n".join(lines)


def csv_safe_cell(value: Any) -> Any:
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return f"'{value}"
    return value


def prepare_history_export_row(row: tuple[Any, ...]) -> tuple[Any, ...]:
    values = list(row)
    if len(values) >= 4 and values[1] in {"PASS_GEN", "PASSWORD"}:
        values[3] = "Password generated; secret redacted for security."
    return tuple(csv_safe_cell(value) for value in values)


async def cancel_flow(message: Message, state: FSMContext) -> bool:
    if message.text and message.text.strip() == "/start":
        await state.clear()
        await handle_start(message, state)
        return True
    if message.text in {
        DEFEND_PATCH,
        ASSET_DISCOVERY,
        CRYPTO_RADAR,
        ATTACK_SIMULATOR,
        MY_STATS,
        HELP,
    }:
        await state.clear()
        await message.answer(
            "The current request was cancelled. Please choose the menu action again.",
            parse_mode="HTML",
            reply_markup=main_keyboard,
        )
        return True
    return False


@dp.message(CommandStart())
async def handle_start(message: Message, state: FSMContext) -> None:
    """Save the Telegram user in MySQL and show the main menu."""
    await state.clear()
    if message.from_user is None:
        logger.warning("Received /start without sender information")
        await message.answer(
            "I couldn't identify your Telegram account.",
            reply_markup=main_keyboard,
        )
        return
    if db_pool is None:
        await message.answer(
            "The database is unavailable right now. Please try again later.",
            reply_markup=main_keyboard,
        )
        return

    user = message.from_user
    try:
        async with acquire_db_connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute(
    """
    INSERT INTO users (telegram_id, username, first_name)
    VALUES (%s, %s, %s) AS new_val
    ON DUPLICATE KEY UPDATE
        username = new_val.username,
        first_name = new_val.first_name
    """,
    (user.id, user.username, user.first_name),
)
    except (aiomysql.MySQLError, RuntimeError):
        logger.exception("Could not save user %s in MySQL", user.id)
        await message.answer(
            "I couldn't save your account details because the database connection "
            "failed. Please try again later.",
            reply_markup=main_keyboard,
        )
        return

    await message.answer(
        f"Welcome, {html.escape(user.first_name or 'there')}!\n"
        "Choose an option from the menu below to get started.",
        reply_markup=main_keyboard,
    )


@dp.message(F.text == IP_DOMAIN_LOOKUP)
async def begin_ip_lookup(message: Message, state: FSMContext) -> None:
    await state.set_state(SearchStates.waiting_for_ip_domain)
    await message.answer(
        "Send an IP address or public domain name to look up. Send /start to cancel.",
        reply_markup=main_keyboard,
    )


@dp.message(F.text == HEADER_ANALYSIS)
async def begin_header_analysis(message: Message, state: FSMContext) -> None:
    await state.set_state(SearchStates.waiting_for_url)
    await message.answer(
        "Send a public HTTP or HTTPS URL to analyze (for example, "
        "https://example.com). Send /start to cancel.",
        reply_markup=main_keyboard,
    )


@dp.message(F.text == EMAIL_LEAK_CHECK)
async def begin_email_check(message: Message, state: FSMContext) -> None:
    await state.set_state(SearchStates.waiting_for_email)
    await message.answer(
        "Send an email address to check against XposedOrNot's public breach database. "
        "Send /start to cancel.",
        reply_markup=main_keyboard,
    )


@dp.message(F.text == DEFEND_PATCH)
async def begin_patch_generation(message: Message, state: FSMContext) -> None:
    await state.set_state(SearchStates.waiting_for_patch_context)
    await message.answer(
        "Describe your Nginx deployment and security requirements (for example, "
        "application type, TLS termination, and expected request limits). "
        "Do not include passwords, private keys, or other secrets. Send /start to cancel.",
        parse_mode="HTML",
        reply_markup=main_keyboard,
    )


@dp.message(F.text == ASSET_DISCOVERY)
async def begin_asset_discovery(message: Message, state: FSMContext) -> None:
    await state.set_state(SearchStates.waiting_for_asset_domain)
    await message.answer(
        "Send a public domain name to check certificate transparency and archived "
        "URLs. Send /start to cancel.",
        parse_mode="HTML",
        reply_markup=main_keyboard,
    )


@dp.message(F.text == CRYPTO_RADAR)
async def begin_crypto_radar(message: Message, state: FSMContext) -> None:
    await state.set_state(SearchStates.waiting_for_crypto_input)
    await message.answer(
        "Send a public crypto address, email address, or suspicious message for "
        "risk analysis. Never send a seed phrase, private key, password, or "
        "one-time code. Send /start to cancel.",
        parse_mode="HTML",
        reply_markup=main_keyboard,
    )


@dp.message(F.text == ATTACK_SIMULATOR)
async def begin_attack_simulator(message: Message, state: FSMContext) -> None:
    await state.set_state(SearchStates.waiting_for_attack_context)
    await message.answer(
        "Describe telemetry for a system you own or are authorized to assess "
        "(for example, exposed services, headers, or known assets). The report "
        "focuses on high-level defensive threat modeling. Send /start to cancel.",
        parse_mode="HTML",
        reply_markup=main_keyboard,
    )


@dp.message(F.text == GENERATE_PASSWORD)
async def generate_password(message: Message, state: FSMContext) -> None:
    await state.clear()
    password = generate_secure_password()

    saved = await record_history(
        message,
        "PASSWORD",
        "16-character password request",
        "Password generated successfully; secret not stored.",
    )
    notice = (
        ""
        if saved
        else "\n\nThe password was generated, but its history could not be saved."
    )
    await message.answer(
        "Your secure 16-character password:\n"
        f"<code>{html.escape(password)}</code>{notice}",
        parse_mode="HTML",
        reply_markup=main_keyboard,
    )


@dp.message(F.text == MY_STATS)
async def show_stats(message: Message, state: FSMContext) -> None:
    await state.clear()
    if message.from_user is None:
        await message.answer(
            "I couldn't identify your Telegram account.", reply_markup=main_keyboard
        )
        return

    try:
        async with acquire_db_connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute(
                    "SELECT COUNT(*) FROM search_history WHERE telegram_id = %s",
                    (message.from_user.id,),
                )
                count_row = await cursor.fetchone()
                await cursor.execute(
                    """
                    SELECT search_type, query_data, created_at
                    FROM search_history
                    WHERE telegram_id = %s
                    ORDER BY created_at DESC, id DESC
                    LIMIT 3
                    """,
                    (message.from_user.id,),
                )
                recent_rows = await cursor.fetchall()
    except (aiomysql.MySQLError, RuntimeError):
        logger.exception(
            "Could not retrieve statistics for user %s", message.from_user.id
        )
        await message.answer(
            "I couldn't retrieve your history because the database connection failed. "
            "Please try again later.",
            reply_markup=main_keyboard,
        )
        return

    total = count_row[0] if count_row else 0
    recent_lines = []
    for search_type, query_data, created_at in recent_rows:
        date_text = created_at.strftime("%Y-%m-%d %H:%M:%S") if created_at else "Unknown"
        recent_lines.append(
            f"• {html.escape(str(search_type or 'Unknown'))}: "
            f"<code>{html.escape(str(query_data or ''))}</code> "
            f"({html.escape(date_text)})"
        )
    recent_text = "\n".join(recent_lines) if recent_lines else "No history yet."
    await message.answer(
        f"<b>My Stats &amp; History</b>\nTotal recorded queries: <b>{total}</b>\n\n"
        f"<b>Last 3 queries</b>\n{recent_text}",
        parse_mode="HTML",
        reply_markup=history_keyboard,
    )


@dp.message(F.text == HELP)
async def show_help(message: Message, state: FSMContext) -> None:
    await state.clear()
    await message.answer(
        "<b>CyberShield &amp; Intelligence Hub</b>\n\n"
        "• Defend &amp; Patch Config: generate hardened Nginx guidance with OpenRouter AI.\n"
        "• Asset &amp; Archive Discovery: check crt.sh and Wayback Machine records.\n"
        "• Crypto &amp; Leak Radar: get AI-assisted scam-risk guidance for public inputs.\n"
        "• Attack Path Simulator: create high-level defensive threat models for "
        "authorized systems.\n"
        "• My Stats &amp; History: review and export your recorded activity.\n\n"
        "Search queries and results are stored in MySQL history. Asset discovery "
        "contacts crt.sh and the Wayback Machine; AI features send submitted context "
        "to OpenRouter. Never submit passwords, private keys, or seed phrases.",
        parse_mode="HTML",
        reply_markup=main_keyboard,
    )


@dp.message(Command("admin"))
async def show_admin_stats(message: Message) -> None:
    if message.from_user is None or ADMIN_ID == 0 or message.from_user.id != ADMIN_ID:
        await message.answer("This command is restricted to the bot administrator.")
        return
    try:
        async with acquire_db_connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute("SELECT COUNT(*) FROM users")
                user_row = await cursor.fetchone()
                await cursor.execute("SELECT COUNT(*) FROM search_history")
                scan_row = await cursor.fetchone()
                await cursor.execute(
                    """
                    SELECT search_type, COUNT(*) AS usage_count
                    FROM search_history
                    GROUP BY search_type
                    ORDER BY usage_count DESC, search_type ASC
                    LIMIT 3
                    """
                )
                top_features = await cursor.fetchall()
    except (aiomysql.MySQLError, RuntimeError):
        logger.exception("Could not retrieve administrator statistics")
        await message.answer(
            "Administrator statistics are unavailable because the database "
            "connection failed. Please try again later.",
            reply_markup=main_keyboard,
        )
        return

    popular = (
        "\n".join(
            f"• {html.escape(str(feature))}: {count}"
            for feature, count in top_features
        )
        or "No recorded activity yet."
    )
    await message.answer(
        "<b>Administrator Dashboard</b>\n"
        f"Total users: <b>{user_row[0] if user_row else 0}</b>\n"
        f"Total scans / actions: <b>{scan_row[0] if scan_row else 0}</b>\n\n"
        f"<b>Top 3 features</b>\n{popular}",
        parse_mode="HTML",
        reply_markup=main_keyboard,
    )


@dp.message(SearchStates.waiting_for_ip_domain)
async def check_ip_or_domain(message: Message, state: FSMContext) -> None:
    if await cancel_flow(message, state):
        return
    if message.text is None:
        await message.answer("Please send an IP address or domain name as text.")
        return

    query = message.text.strip()
    target = validate_lookup_target(query)
    if target is None:
        await message.answer(
            "That doesn't look like a valid public IP address or domain. Please try again."
        )
        return

    await state.clear()
    url = (
        f"http://ip-api.com/json/{quote(target, safe='')}"
        "?fields=status,message,country,city,isp,org,as,query"
    )
    timeout = aiohttp.ClientTimeout(total=10)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                response.raise_for_status()
                data = await response.json()
    except asyncio.TimeoutError:
        await message.answer(
            "The IP lookup timed out. Please try again later.",
            reply_markup=main_keyboard,
        )
        return
    except (aiohttp.ClientError, ValueError):
        logger.exception("IP lookup failed for query %r", target)
        await message.answer(
            "The IP lookup service is unavailable right now. Please try again later.",
            reply_markup=main_keyboard,
        )
        return

    if not isinstance(data, dict) or data.get("status") != "success":
        reason = (
            data.get("message", "The address could not be resolved.")
            if isinstance(data, dict)
            else "The address could not be resolved."
        )
        await message.answer(
            f"Invalid IP address or domain: {html.escape(str(reason))}",
            reply_markup=main_keyboard,
        )
        return

    fields = (
        ("Country", data.get("country")),
        ("City", data.get("city")),
        ("ISP", data.get("isp")),
        ("Organization", data.get("org")),
        ("AS", data.get("as")),
        ("IP", data.get("query")),
    )
    result = "\n".join(
        f"<b>{html.escape(label)}:</b> {html.escape(str(value or 'Unknown'))}"
        for label, value in fields
    )
    saved = await record_history(message, "IP_DOMAIN", target, result)
    warning = (
        ""
        if saved
        else "\n\nThe lookup succeeded, but its history could not be saved."
    )
    await message.answer(
        f"🔍 <b>Network lookup results</b>\n\n{result}{warning}",
        parse_mode="HTML",
        reply_markup=main_keyboard,
    )


@dp.message(SearchStates.waiting_for_url)
async def analyze_headers(message: Message, state: FSMContext) -> None:
    if await cancel_flow(message, state):
        return
    if message.text is None:
        await message.answer("Please send a URL as text.")
        return

    target = message.text.strip()
    if len(target) > 2048:
        await message.answer("That URL is too long. Please send a shorter URL.")
        return
    try:
        parsed = urlsplit(target)
        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError
        target = parsed.geturl()
    except ValueError:
        await message.answer(
            "Please send a valid HTTP or HTTPS URL without embedded credentials."
        )
        return
    try:
        literal_address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        literal_address = None
    if literal_address is not None and not literal_address.is_global:
        await message.answer(
            "This URL uses a private or local network address. "
            "Only publicly routable hosts can be scanned.",
            reply_markup=main_keyboard,
        )
        return

    await state.clear()
    timeout = aiohttp.ClientTimeout(total=12)
    connector = aiohttp.TCPConnector(resolver=PublicResolver())
    try:
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            async with session.head(
                target, allow_redirects=False, raise_for_status=False
            ) as response:
                header_report = format_header_scan(response.headers)
                status_code = response.status
                result = f"HTTP status: {status_code}\n{header_report}"
    except UnsafeTargetError:
        await message.answer(
            "This URL resolves to a private or local network address. "
            "Only publicly routable hosts can be scanned.",
            reply_markup=main_keyboard,
        )
        return
    except asyncio.TimeoutError:
        await message.answer(
            "The HTTP header scan timed out. Please try again later.",
            reply_markup=main_keyboard,
        )
        return
    except (aiohttp.ClientError, OSError, ValueError):
        logger.exception("HTTP header scan failed for URL %r", target)
        await message.answer(
            "I couldn't reach that URL. Check the address and try again.",
            reply_markup=main_keyboard,
        )
        return

    saved = await record_history(message, "HEADER_SCAN", target, result)
    warning = "" if saved else "\n\nThe scan succeeded, but its history could not be saved."
    await message.answer(
        f"🛡️ <b>HTTP Header Analysis</b>\n"
        f"URL: <code>{html.escape(target)}</code>\n"
        f"HTTP status: <b>{status_code}</b>\n\n"
        f"{header_report}{warning}",
        parse_mode="HTML",
        reply_markup=main_keyboard,
    )


@dp.message(SearchStates.waiting_for_email)
async def check_email_leaks(message: Message, state: FSMContext) -> None:
    if await cancel_flow(message, state):
        return
    if message.text is None:
        await message.answer("Please send an email address as text.")
        return

    email = message.text.strip()
    if not is_valid_email(email):
        await message.answer("That doesn't look like a valid email address. Please try again.")
        return

    await state.clear()
    url = f"https://api.xposedornot.com/v1/check-email/{quote(email, safe='')}"
    timeout = aiohttp.ClientTimeout(total=12)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                if response.status not in {200, 404}:
                    response.raise_for_status()
                data = await response.json(content_type=None)
    except asyncio.TimeoutError:
        result = "Breach status unavailable: the public API request timed out."
        logger.warning("Email breach lookup timed out")
        saved = await record_history(message, "EMAIL_CHECK", email, result)
        suffix = "" if saved else " History could not be saved."
        await message.answer(
            "The breach-check service timed out, so I couldn't determine whether "
            f"this address appears in known breaches.{suffix}",
            reply_markup=main_keyboard,
        )
        return
    except (aiohttp.ClientError, ValueError):
        logger.exception("Email breach lookup failed")
        result = "Breach status unavailable: the public API could not be reached."
        saved = await record_history(message, "EMAIL_CHECK", email, result)
        suffix = "" if saved else " History could not be saved."
        await message.answer(
            "The breach-check service is unavailable, so I couldn't determine whether "
            f"this address appears in known breaches.{suffix}",
            reply_markup=main_keyboard,
        )
        return

    if not isinstance(data, dict):
        logger.warning("Email breach API returned an unexpected response")
        result = "Breach status unavailable: unexpected API response."
        await record_history(message, "EMAIL_CHECK", email, result)
        await message.answer(
            "The breach-check service returned an unexpected response. "
            "Please try again later.",
            reply_markup=main_keyboard,
        )
        return

    breaches = data.get("breaches")
    if isinstance(breaches, list) and breaches and isinstance(breaches[0], list):
        breach_names = [str(name) for name in breaches[0] if name]
    elif isinstance(breaches, list):
        breach_names = [str(name) for name in breaches if name]
    else:
        breach_names = []

    if breach_names:
        listed = ", ".join(html.escape(name) for name in breach_names[:20])
        result = f"Found in {len(breach_names)} known breach(es): {', '.join(breach_names)}"
        response_text = (
            f"⚠️ This address was found in <b>{len(breach_names)}</b> known breach(es):\n"
            f"{listed}"
        )
    elif response.status == 404 or data.get("Error") == "Not found":
        result = "No matching breaches were reported by the public database."
        response_text = "✅ No matching breaches were reported by the public database."
    else:
        logger.warning("Email breach API response did not include a breach result")
        result = "Breach status unavailable: unexpected API response."
        response_text = (
            "The breach-check service returned an unexpected response. "
            "Please try again later."
        )
    saved = await record_history(message, "EMAIL_CHECK", email, result)
    warning = "" if saved else "\n\nThe result was received, but its history could not be saved."
    await message.answer(
        f"📧 <b>Email Breach Check</b>\n{response_text}{warning}",
        parse_mode="HTML",
        reply_markup=main_keyboard,
    )


async def _send_ai_report(
    message: Message,
    target: str,
    raw_data: str,
    mode: str,
    search_type: str,
) -> None:
    try:
        report = await asyncio.wait_for(
            generate_ai_report(target, raw_data=raw_data, mode=mode), timeout=90
        )
        result = report
        heading = f"<b>{html.escape(target)}</b>\n\n"
    except asyncio.TimeoutError:
        logger.warning("%s report timed out", search_type)
        result = "<i>The AI report timed out. Please try again later.</i>"
        heading = ""
    except (APIError, RuntimeError, ValueError):
        logger.exception("%s report failed", search_type)
        result = (
            "<i>The AI report service is unavailable or not configured. "
            "Please try again later.</i>"
        )
        heading = ""

    saved = await record_history(message, search_type, raw_data, result)
    warning = (
        ""
        if saved
        else "\n\n<i>The result could not be saved in your history.</i>"
    )
    await message.answer(
        f"{heading}{result}{warning}",
        parse_mode="HTML",
        reply_markup=main_keyboard,
    )


@dp.message(SearchStates.waiting_for_patch_context)
async def generate_patch_config(message: Message, state: FSMContext) -> None:
    if await cancel_flow(message, state):
        return
    if message.text is None or not message.text.strip():
        await message.answer("Please describe the Nginx setup as text.", parse_mode="HTML")
        return
    context = message.text.strip()
    if len(context) > 3500:
        await message.answer(
            "Please keep the configuration request under 3,500 characters.",
            parse_mode="HTML",
        )
        return

    await state.clear()
    await _send_ai_report(
        message,
        "Nginx security configuration",
        context,
        "PATCH_GEN",
        "PATCH_GEN",
    )


@dp.message(SearchStates.waiting_for_asset_domain)
async def discover_assets(message: Message, state: FSMContext) -> None:
    if await cancel_flow(message, state):
        return
    if message.text is None:
        await message.answer("Please send a public domain name as text.", parse_mode="HTML")
        return

    query = message.text.strip()
    domain = validate_lookup_target(query)
    if domain is None:
        await message.answer(
            "That doesn't look like a valid domain. Please try again.",
            parse_mode="HTML",
        )
        return
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        await message.answer(
            "Asset discovery requires a domain name, not an IP address.",
            parse_mode="HTML",
        )
        return

    await state.clear()
    try:
        result = await run_asset_discovery(domain)
    except asyncio.TimeoutError:
        logger.warning("Asset discovery timed out for domain %s", domain)
        result = (
            f"<b>Asset discovery for <code>{html.escape(domain)}</code></b>\n"
            "<i>The public data sources timed out. Please try again later.</i>"
        )
    except (aiohttp.ClientError, ValueError):
        logger.exception("Asset discovery failed for domain %s", domain)
        result = (
            f"<b>Asset discovery for <code>{html.escape(domain)}</code></b>\n"
            "<i>The public data sources returned an error. Please try again later.</i>"
        )

    saved = await record_history(message, "ASSET_DISCOVERY", domain, result)
    warning = (
        ""
        if saved
        else "\n\n<i>The result was received, but its history could not be saved.</i>"
    )
    await message.answer(
        f"{result}{warning}", parse_mode="HTML", reply_markup=main_keyboard
    )


@dp.message(SearchStates.waiting_for_crypto_input)
async def analyze_crypto_risk(message: Message, state: FSMContext) -> None:
    if await cancel_flow(message, state):
        return
    if message.text is None or not message.text.strip():
        await message.answer(
            "Please send an address, email, or message as text.", parse_mode="HTML"
        )
        return
    query = message.text.strip()
    if len(query) > 2000:
        await message.answer(
            "Please keep the risk-analysis input under 2,000 characters.",
            parse_mode="HTML",
        )
        return

    await state.clear()
    await _send_ai_report(
        message, "Crypto and leak risk assessment", query, "CRYPTO_RADAR", "CRYPTO_RADAR"
    )


@dp.message(SearchStates.waiting_for_attack_context)
async def simulate_attack_path(message: Message, state: FSMContext) -> None:
    if await cancel_flow(message, state):
        return
    if message.text is None or not message.text.strip():
        await message.answer("Please send system telemetry as text.", parse_mode="HTML")
        return
    context = message.text.strip()
    if len(context) > 3500:
        await message.answer(
            "Please keep the telemetry under 3,500 characters.", parse_mode="HTML"
        )
        return

    await state.clear()
    await _send_ai_report(
        message,
        "Authorized-environment threat model",
        context,
        "ATTACK_SIMULATOR",
        "ATTACK_SIMULATOR",
    )


@dp.callback_query(F.data == "export_history")
async def export_history_callback(callback: CallbackQuery) -> None:
    if callback.from_user is None:
        await callback.answer("I couldn't identify your Telegram account.", show_alert=True)
        return
    try:
        async with acquire_db_connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute(
                    """
                    SELECT id, search_type, query_data, result_data, created_at
                    FROM search_history
                    WHERE telegram_id = %s
                    ORDER BY created_at DESC, id DESC
                    """,
                    (callback.from_user.id,),
                )
                rows = await cursor.fetchall()
    except (aiomysql.MySQLError, RuntimeError):
        logger.exception(
            "Could not export history for user %s", callback.from_user.id
        )
        await callback.answer(
            "History export is unavailable because the database connection failed.",
            show_alert=True,
        )
        return

    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(("id", "search_type", "query_data", "result_data", "created_at"))
    writer.writerows(prepare_history_export_row(row) for row in rows)
    document = BufferedInputFile(
        output.getvalue().encode("utf-8-sig"),
        filename=f"history_{callback.from_user.id}.csv",
    )
    if callback.message is None:
        await callback.answer("The export message is no longer available.", show_alert=True)
        return
    await callback.bot.send_document(
        chat_id=callback.message.chat.id,
        document=document,
        caption="Your query history export.",
    )
    await callback.answer()


async def main() -> None:
    """Initialize the database and start the Telegram bot."""
    global db_pool

    if not BOT_TOKEN or BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
        raise RuntimeError(
            "BOT_TOKEN is not configured. Set it in the BOT_TOKEN environment variable."
        )

    bot = Bot(
        token=BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
    try:
        db_pool = await initialize_database()
        await dp.start_polling(bot)
    finally:
        if db_pool is not None:
            db_pool.close()
            await db_pool.wait_closed()
            db_pool = None
        await bot.session.close()


if __name__ == "__main__":
    asyncio.run(main())
