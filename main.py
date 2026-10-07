import asyncio
import html
import logging
import os
import secrets
import string
from urllib.parse import quote

import aiohttp
import aiomysql
from aiogram import Bot, Dispatcher, F
from aiogram.filters import CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import KeyboardButton, Message, ReplyKeyboardMarkup


# Set credentials in the environment; do not put secrets in source control.
BOT_TOKEN = os.getenv("BOT_TOKEN", "8825249997:AAGMqFS4Sb31u6TX-mMrNUKAOhWnoXRoLGs")
MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_USER = os.getenv("MYSQL_USER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "S1asag1dan4iks")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "tg_bot_db")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

dp = Dispatcher()
db_pool: aiomysql.Pool | None = None

CHECK_IP_DOMAIN = "🔍 Check IP / Domain"
GENERATE_PASSWORD = "🔐 Generate Password"
MY_STATS = "📊 My Stats"
HELP = "ℹ️ Help"

main_keyboard = ReplyKeyboardMarkup(
    keyboard=[
        [KeyboardButton(text=CHECK_IP_DOMAIN)],
        [KeyboardButton(text=GENERATE_PASSWORD), KeyboardButton(text=MY_STATS)],
        [KeyboardButton(text=HELP)],
    ],
    resize_keyboard=True,
    is_persistent=True,
)


class SearchStates(StatesGroup):
    waiting_for_query = State()


def quote_identifier(identifier: str) -> str:
    """Safely escape a database name for SQL."""
    return f"`{identifier.replace('`', '``')}`"


async def initialize_database() -> aiomysql.Pool:
    """Create required tables and return the MySQL connection pool."""
    database_name = quote_identifier(MYSQL_DATABASE)

    connection = await aiomysql.connect(
        host=MYSQL_HOST,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
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
        autocommit=True,
        minsize=1,
        maxsize=10,
    )
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

    return pool


async def save_search_history(
    telegram_id: int, search_type: str, query_data: str, result_data: str
) -> None:
    if db_pool is None:
        raise RuntimeError("The database connection has not been initialized.")

    async with db_pool.acquire() as connection:
        async with connection.cursor() as cursor:
            await cursor.execute(
                """
                INSERT INTO search_history
                    (telegram_id, search_type, query_data, result_data)
                VALUES (%s, %s, %s, %s)
                """,
                (telegram_id, search_type, query_data, result_data),
            )


def escape_markdown(value: str) -> str:
    for character in ("\\", "_", "*", "`", "["):
        value = value.replace(character, f"\\{character}")
    return value


@dp.message(F.text == CHECK_IP_DOMAIN)
async def begin_ip_check(message: Message, state: FSMContext) -> None:
    await state.set_state(SearchStates.waiting_for_query)
    await message.answer(
        "Send an IP address or domain name to check. Send /start to cancel.",
        reply_markup=main_keyboard,
    )


@dp.message(F.text == GENERATE_PASSWORD)
async def generate_password(message: Message, state: FSMContext) -> None:
    await state.clear()
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
    password = "".join(characters)

    history_warning = ""
    if message.from_user is not None:
        try:
            await save_search_history(
                message.from_user.id,
                "PASS_GEN",
                "16-character password",
                password,
            )
        except (aiomysql.MySQLError, RuntimeError):
            logger.exception(
                "Could not save generated-password history for user %s",
                message.from_user.id,
            )
            history_warning = (
                "\n\nYour password was generated, but its history could not be saved."
            )

    await message.answer(
        f"Your secure 16-character password:\n<code>{html.escape(password)}</code>"
        f"{html.escape(history_warning)}",
        parse_mode="HTML",
        reply_markup=main_keyboard,
    )


@dp.message(F.text == MY_STATS)
async def show_stats(message: Message, state: FSMContext) -> None:
    await state.clear()
    if message.from_user is None:
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

    try:
        async with db_pool.acquire() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute(
                    "SELECT COUNT(*) FROM search_history WHERE telegram_id = %s",
                    (message.from_user.id,),
                )
                row = await cursor.fetchone()
    except aiomysql.MySQLError:
        logger.exception(
            "Could not retrieve statistics for user %s", message.from_user.id
        )
        await message.answer(
            "I couldn't retrieve your statistics because the database connection failed. "
            "Please try again later.",
            reply_markup=main_keyboard,
        )
        return

    total = row[0] if row else 0
    await message.answer(
        f"You have performed {total} scan(s) or password generation(s).",
        reply_markup=main_keyboard,
    )


@dp.message(F.text == HELP)
async def show_help(message: Message, state: FSMContext) -> None:
    await state.clear()
    await message.answer(
        "Cybersecurity & OSINT Toolkit\n\n"
        "• Check an IP address or domain for available geolocation and network details.\n"
        "• Generate a cryptographically secure 16-character password.\n"
        "• View the total number of your scans and password generations.\n\n"
        "Search results and password generation events are recorded in your account history.",
        reply_markup=main_keyboard,
    )


@dp.message(SearchStates.waiting_for_query)
async def check_ip_or_domain(message: Message, state: FSMContext) -> None:
    if message.text is None:
        await message.answer("Please send an IP address or domain name as text.")
        return

    query = message.text.strip()
    if query == "/start":
        await state.clear()
        await message.answer(
            "Search cancelled. Choose an option from the menu below.",
            reply_markup=main_keyboard,
        )
        return
    if not query or len(query) > 253 or any(char.isspace() for char in query):
        await message.answer(
            "That doesn't look like a valid IP address or domain. Please try again."
        )
        return

    await state.clear()
    url = (
        f"http://ip-api.com/json/{quote(query, safe='')}"
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
        logger.exception("IP lookup failed for query %r", query)
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
        ("IP", data.get("query")),
    )
    result = "\n".join(
        f"*{label}:* {escape_markdown(str(value or 'Unknown'))}"
        for label, value in fields
    )
    history_warning = ""
    if message.from_user is not None:
        try:
            await save_search_history(
                message.from_user.id,
                "IP_CHECK",
                query,
                result,
            )
        except (aiomysql.MySQLError, RuntimeError):
            logger.exception(
                "Could not save IP-check history for user %s", message.from_user.id
            )
            history_warning = (
                "\n\nYour lookup succeeded, but its history could not be saved "
                "because the database is unavailable."
            )

    await message.answer(
        f"🔍 *Network lookup results*\n\n{result}{history_warning}",
        parse_mode="Markdown",
        reply_markup=main_keyboard,
    )


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
        async with db_pool.acquire() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute(
                    """
                    INSERT INTO users (telegram_id, username, first_name)
                    VALUES (%s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        username = VALUES(username),
                        first_name = VALUES(first_name)
                    """,
                    (user.id, user.username, user.first_name),
                )
    except aiomysql.MySQLError:
        logger.exception("Could not save user %s in MySQL", user.id)
        await message.answer(
            "I couldn't save your account details because the database connection failed. "
            "Please try again later.",
            reply_markup=main_keyboard,
        )
        return

    await message.answer(
        f"Welcome, {user.first_name or 'there'}!\n"
        "Choose an option from the menu below to get started.",
        reply_markup=main_keyboard,
    )


async def main() -> None:
    """Initialize the database and start the Telegram bot."""
    global db_pool

    if not BOT_TOKEN:
        raise RuntimeError(
            "BOT_TOKEN is not set. Define it in the BOT_TOKEN environment variable."
        )

    bot = Bot(token=BOT_TOKEN)
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
