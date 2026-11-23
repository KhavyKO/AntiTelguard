import re
import hashlib
import logging
from urllib.parse import urlparse
import httpx

from aiogram import Router, F, Bot
from aiogram.types import Message, ReactionTypeEmoji

from app.config import AppConfig
from app.threat_intel.base import BaseScanner, ScanResult
from app.db import log_scan_event

logger = logging.getLogger(__name__)
router = Router()

URL_REGEX = re.compile(r"https?://[^\s<>\"']+")

async def apply_reaction(message: Message, emoji: str):
    if not emoji:
        return
    try:
        await message.react([ReactionTypeEmoji(emoji=emoji)])
    except Exception as e:
        logger.warning(f"Could not apply reaction '{emoji}' to msg {message.message_id}: {e}")

async def process_verdict(
    bot: Bot,
    message: Message,
    item_type: str,
    item_name: str,
    target_hash: str,
    result: ScanResult,
    config: AppConfig
):
    chat_title = message.chat.title if message.chat.title else "Direct Message"
    is_threat = (
        result.verdict == "THREAT" and (
            result.malicious >= config.malicious_threshold or
            result.suspicious >= config.suspicious_threshold
        )
    )

    action_taken = "NONE"

    if result.verdict == "CLEAN":
        await apply_reaction(message, config.clean_reaction)
        action_taken = "REACT_CLEAN"

    elif result.verdict == "UNKNOWN":
        await apply_reaction(message, config.unknown_reaction)
        action_taken = "REACT_UNKNOWN"

    elif is_threat:
        await apply_reaction(message, config.threat_reaction)
        action_taken = config.threat_action

        user_mention = f"@{message.from_user.username}" if message.from_user.username else message.from_user.full_name
        vt_link_text = f'\n🔗 <a href="{result.permalink}">View VirusTotal Report</a>' if result.permalink else ""

        alert_text = (
            f"🚨 <b>THREAT DETECTED ({item_type})</b>\n\n"
            f"<b>Target:</b> <code>{item_name[:60]}</code>\n"
            f"<b>Malicious Flags:</b> {result.malicious}\n"
            f"<b>Suspicious Flags:</b> {result.suspicious}\n"
            f"<b>Sender:</b> {user_mention}"
            f"{vt_link_text}\n\n"
            f"<i>⚠️ Do not open or run this {item_type.lower()}!</i>"
        )

        if config.threat_action == "DELETE_AND_ALERT":
            try:
                await message.delete()
                await bot.send_message(
                    chat_id=message.chat.id,
                    text=f"🛡️ <b>Malicious message removed!</b>\n\n{alert_text}",
                    parse_mode="HTML",
                    disable_web_page_preview=True
                )
            except Exception as e:
                logger.error(f"Failed to delete message: {e}")
                # Fallback to reply
                await message.reply(alert_text, parse_mode="HTML", disable_web_page_preview=True)

        elif config.threat_action == "REPLY_ALERT":
            try:
                await message.reply(alert_text, parse_mode="HTML", disable_web_page_preview=True)
            except Exception as e:
                logger.error(f"Failed to send reply alert: {e}")

    # Extract sender details
    user = message.from_user
    if user:
        if user.username:
            sender_info = f"@{user.username}"
        elif user.full_name:
            sender_info = f"{user.full_name}"
        else:
            sender_info = f"User {user.id}"
    else:
        sender_info = "Channel / Anonymous"

    await log_scan_event(
        event_type=item_type,
        target=item_name,
        target_hash=target_hash,
        malicious=result.malicious,
        suspicious=result.suspicious,
        verdict=result.verdict,
        action_taken=action_taken,
        chat_title=chat_title,
        sender=sender_info
    )

def setup_handlers(router: Router, scanner: BaseScanner, config_provider):
    @router.message(F.document | F.video | F.audio)
    async def handle_file(message: Message, bot: Bot):
        config: AppConfig = config_provider()
        if not config.scan_files:
            return

        media = message.document or message.video or message.audio
        if not media:
            return

        # Check maximum allowed file size
        max_bytes = config.max_file_size_mb * 1024 * 1024
        if media.file_size > max_bytes:
            logger.info(f"File {media.file_id} exceeds {config.max_file_size_mb}MB limit. Skipping.")
            return

        try:
            file_info = await bot.get_file(media.file_id)
            download_url = f"https://api.telegram.org/file/bot{bot.token}/{file_info.file_path}"
        except Exception as e:
            logger.error(f"Error fetching file path for {media.file_id}: {e}")
            return

        # Pure in-memory streaming: Hash calculated in RAM without saving to disk
        sha256 = hashlib.sha256()
        try:
            async with httpx.AsyncClient(timeout=45.0) as client:
                async with client.stream("GET", download_url) as stream:
                    if stream.status_code != 200:
                        logger.error(f"Failed to download stream: HTTP {stream.status_code}")
                        return
                    async for chunk in stream.aiter_bytes(chunk_size=65536):
                        sha256.update(chunk)
        except Exception as e:
            logger.error(f"Error streaming file {media.file_id}: {e}")
            return

        file_hash = sha256.hexdigest()
        file_name = getattr(media, "file_name", "Telegram_Media")

        logger.info(f"Scanned file: {file_name} -> SHA256: {file_hash}")
        result = await scanner.scan_file_hash(file_hash)
        await process_verdict(bot, message, "FILE", file_name, file_hash, result, config)

    @router.message(F.text | F.caption)
    async def handle_text_urls(message: Message, bot: Bot):
        config: AppConfig = config_provider()
        if not config.scan_urls:
            return

        content = message.text or message.caption or ""
        urls = URL_REGEX.findall(content)
        if not urls:
            return

        for url in set(urls):
            parsed = urlparse(url)
            if not parsed.netloc:
                continue

            logger.info(f"Scanning URL: {url}")
            result = await scanner.scan_url(url)
            await process_verdict(bot, message, "URL", url, result.target_hash or "", result, config)
