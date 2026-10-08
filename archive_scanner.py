import asyncio
import html
import ipaddress
import logging
import re

import aiohttp

logger = logging.getLogger(__name__)

_DOMAIN_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\Z")
_REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=15)
_USER_AGENT = "CyberShield-Intelligence-Hub/1.0"


def _normalize_domain(domain: str) -> str:
    candidate = domain.strip().rstrip(".")
    try:
        normalized = candidate.encode("idna").decode("ascii").lower()
        ipaddress.ip_address(normalized)
    except ValueError:
        pass
    except UnicodeError as error:
        raise ValueError("Enter a valid public domain name.") from error
    else:
        raise ValueError("Asset discovery requires a domain name, not an IP address.")

    labels = normalized.split(".")
    if (
        len(normalized) > 253
        or len(labels) < 2
        or any(
            not label or len(label) > 63 or not _DOMAIN_LABEL.fullmatch(label)
            for label in labels
        )
    ):
        raise ValueError("Enter a valid public domain name.")
    return normalized


async def fetch_subdomains(domain: str) -> list[str]:
    """Fetch certificate names for a domain from the public crt.sh API."""
    normalized = _normalize_domain(domain)
    url = "https://crt.sh/"
    params = {"q": f"%.{normalized}", "output": "json"}
    headers = {"User-Agent": _USER_AGENT}

    async with aiohttp.ClientSession(
        timeout=_REQUEST_TIMEOUT, headers=headers
    ) as session:
        async with session.get(url, params=params) as response:
            response.raise_for_status()
            data = await response.json(content_type=None)

    if not isinstance(data, list):
        raise ValueError("crt.sh returned an unexpected response.")

    discovered: set[str] = set()
    suffix = f".{normalized}"
    for entry in data:
        if not isinstance(entry, dict):
            continue
        names = entry.get("name_value")
        if not isinstance(names, str):
            continue
        for name in names.splitlines():
            hostname = name.strip().lower().removeprefix("*.")
            labels = hostname.split(".")
            if (
                (hostname == normalized or hostname.endswith(suffix))
                and len(hostname) <= 253
                and all(
                    label and len(label) <= 63 and _DOMAIN_LABEL.fullmatch(label)
                    for label in labels
                )
            ):
                discovered.add(hostname)
    return sorted(discovered)[:50]


async def fetch_wayback_urls(domain: str) -> list[str]:
    """Fetch distinct archived URLs for a domain from the Wayback CDX API."""
    normalized = _normalize_domain(domain)
    url = "https://web.archive.org/cdx/search/cdx"
    params = {
        "url": f"*.{normalized}/*",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "limit": "20",
    }
    headers = {"User-Agent": _USER_AGENT}

    async with aiohttp.ClientSession(
        timeout=_REQUEST_TIMEOUT, headers=headers
    ) as session:
        async with session.get(url, params=params) as response:
            response.raise_for_status()
            data = await response.json(content_type=None)

    if not isinstance(data, list):
        raise ValueError("The Wayback Machine returned an unexpected response.")

    urls: list[str] = []
    for row in data[1:]:
        if isinstance(row, list) and row and isinstance(row[0], str):
            urls.append(row[0])
    return urls


async def run_asset_discovery(domain: str) -> str:
    """Combine certificate transparency and Wayback results as safe Telegram HTML."""
    normalized = _normalize_domain(domain)
    subdomains_result, wayback_result = await asyncio.gather(
        fetch_subdomains(normalized),
        fetch_wayback_urls(normalized),
        return_exceptions=True,
    )

    def format_section(
        title: str, result: list[str] | BaseException, limit: int
    ) -> tuple[str, int | None]:
        if isinstance(result, BaseException):
            if not isinstance(result, Exception):
                raise result
            logger.warning("%s lookup failed for %s: %s", title, normalized, result)
            return f"<i>{title} lookup is temporarily unavailable.</i>", None
        if not result:
            return "No results found.", 0
        rendered_items: list[str] = []
        for item in result[:limit]:
            printable_item = "".join(char for char in item if char.isprintable())
            if title == "Wayback Machine" and len(printable_item) > 180:
                printable_item = f"{printable_item[:177]}..."
            line = f"• <code>{html.escape(printable_item, quote=True)}</code>"
            if sum(map(len, rendered_items)) + len(line) > 1400:
                break
            rendered_items.append(line)
        items = "\n".join(rendered_items)
        remaining = len(result) - len(rendered_items)
        if remaining > 0:
            items += f"\n<i>{remaining} more results omitted.</i>"
        return items, len(result)

    subdomains_text, subdomains_count = format_section(
        "Certificate transparency", subdomains_result, 20
    )
    wayback_text, wayback_count = format_section(
        "Wayback Machine", wayback_result, 10
    )
    if subdomains_count is None and wayback_count is None:
        status = "\n\n<i>Both public data sources were unavailable; try again later.</i>"
    else:
        status = ""

    return (
        f"<b>Asset discovery for <code>{html.escape(normalized)}</code></b>\n\n"
        f"<b>Subdomains ({subdomains_count if subdomains_count is not None else 'unavailable'}):</b>\n"
        f"{subdomains_text}\n\n"
        f"<b>Archived URLs ({wayback_count if wayback_count is not None else 'unavailable'}):</b>\n"
        f"{wayback_text}{status}"
    )
