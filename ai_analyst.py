import html
import os
from html.parser import HTMLParser
from urllib.parse import urlsplit

from openai import AsyncOpenAI

SYSTEM_PROMPTS = {
    "PATCH_GEN": (
        "You are a defensive DevSecOps engineer. Generate a hardened Nginx "
        "configuration appropriate to the user's stated environment. Include "
        "safe security headers, TLS guidance, request limits, and rate limiting "
        "where context permits. Do not invent application-specific paths or "
        "secrets. Return valid Telegram-compatible HTML, with copyable Nginx "
        "configuration in <pre><code>...</code></pre>, then concise explanations "
        "and testing/rollback cautions. Escape HTML special characters inside "
        "the code block."
    ),
    "CRYPTO_RADAR": (
        "You are a crypto fraud and breach-risk analyst. Assess the supplied "
        "address, email, or text only for observable scam indicators and "
        "defensive safety steps. Do not claim to query live blockchains, breach "
        "databases, or identify an owner unless evidence is provided. Never "
        "request seed phrases, passwords, private keys, or one-time codes. "
        "Clearly distinguish evidence from uncertainty and give a cautious "
        "risk grade (LOW / MEDIUM / HIGH / UNKNOWN). Return valid "
        "Telegram-compatible HTML."
    ),
    "ATTACK_SIMULATOR": (
        "You are a defensive threat-modeling specialist. For systems the user "
        "is authorized to assess, describe a hypothetical attack path only at "
        "a high level using supplied telemetry. Do not provide exploit "
        "instructions, payloads, credential theft, persistence, evasion, or "
        "steps against real third-party targets. Focus each stage on the "
        "exposure, potential impact, detection opportunities, and concrete "
        "countermeasures. State assumptions and finish with prioritized "
        "defensive actions. Return valid Telegram-compatible HTML."
    ),
}

_ALLOWED_TAGS = {
    "a",
    "b",
    "blockquote",
    "code",
    "em",
    "i",
    "pre",
    "s",
    "strong",
    "u",
}


class _TelegramHTMLSanitizer(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.open_tags: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in _ALLOWED_TAGS:
            return
        if tag == "a":
            href = next((value for key, value in attrs if key == "href"), None)
            if href:
                parsed = urlsplit(href)
                if parsed.scheme in {"http", "https", "tg"}:
                    self.parts.append(f'<a href="{html.escape(href, quote=True)}">')
                    self.open_tags.append(tag)
                    return
            return
        self.parts.append(f"<{tag}>")
        self.open_tags.append(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag not in self.open_tags:
            return
        while self.open_tags:
            opened = self.open_tags.pop()
            self.parts.append(f"</{opened}>")
            if opened == tag:
                break

    def handle_data(self, data: str) -> None:
        self.parts.append(html.escape(data, quote=False))

    def finish(self) -> str:
        while self.open_tags:
            self.parts.append(f"</{self.open_tags.pop()}>")
        return "".join(self.parts).strip()


def _clean_html(content: str) -> str:
    sanitizer = _TelegramHTMLSanitizer()
    sanitizer.feed(content)
    sanitizer.close()
    cleaned = sanitizer.finish()
    if len(cleaned) > 3600:
        shortened = _TelegramHTMLSanitizer()
        shortened.feed(cleaned[:3500])
        shortened.close()
        cleaned = f"{shortened.finish()}\n<i>Report shortened to fit Telegram.</i>"
    return cleaned or "<i>No report content was returned.</i>"


def _get_client() -> AsyncOpenAI:
    api_key = os.getenv("OPENROUTER_API_KEY", "")
    if not api_key:
        raise RuntimeError(
            "OPENROUTER_API_KEY is not configured. Set it to enable AI reports."
        )
    return AsyncOpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key,
        timeout=30.0,
        max_retries=0,
    )


async def generate_ai_report(target: str, mode: str, raw_data: str) -> str:
    if mode not in SYSTEM_PROMPTS:
        raise ValueError(f"Unsupported AI report mode: {mode}")

    async with _get_client() as client:
        response = await client.chat.completions.create(
            model="openrouter/free",  # Быстрая и стабильная бесплатная модель
            messages=[
                {"role": "system", "content": SYSTEM_PROMPTS[mode]},
                {
                    "role": "user",
                    "content": (
                        f"Target or context:\n{target}\n\n"
                        f"User-provided information:\n{raw_data}"
                    ),
                },
            ],
            temperature=0.3,
            max_tokens=700,
        )
    content = response.choices[0].message.content if response.choices else None
    if not content:
        return "<i>No report content was returned.</i>"
    return _clean_html(content)
