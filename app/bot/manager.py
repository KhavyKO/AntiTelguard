import asyncio
import logging
from typing import Optional, Dict, Any

from aiogram import Bot, Dispatcher
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties

from app.config import AppConfig
from app.threat_intel.virustotal import VirusTotalScanner
from app.bot.handlers import router, setup_handlers

logger = logging.getLogger(__name__)

class BotManager:
    def __init__(self, config_getter, config_saver):
        self.config_getter = config_getter
        self.config_saver = config_saver
        self.status = "STOPPED"  # STOPPED, STARTING, RUNNING, ERROR, AWAITING_CONFIG
        self.error_message: Optional[str] = None
        self.bot_info: Dict[str, Any] = {}

        self.bot: Optional[Bot] = None
        self.dp: Optional[Dispatcher] = None
        self.scanner: Optional[VirusTotalScanner] = None
        self._polling_task: Optional[asyncio.Task] = None

    async def initialize(self):
        config: AppConfig = self.config_getter()
        self.scanner = VirusTotalScanner(
            api_key=config.virustotal_api_key,
            cache_ttl=config.cache_ttl_seconds
        )

        if not config.telegram_bot_token:
            self.status = "AWAITING_CONFIG"
            self.error_message = "Telegram Bot Token is missing. Please configure it in the Web UI."
            return

        await self.start()

    async def start(self) -> bool:
        config: AppConfig = self.config_getter()
        if not config.telegram_bot_token:
            self.status = "AWAITING_CONFIG"
            self.error_message = "Telegram Bot Token is not configured."
            return False

        self.status = "STARTING"
        self.error_message = None

        try:
            # Recreate Bot instance
            self.bot = Bot(
                token=config.telegram_bot_token,
                default=DefaultBotProperties(parse_mode=ParseMode.HTML)
            )

            # Test credentials
            me = await self.bot.get_me()
            self.bot_info = {
                "id": me.id,
                "username": me.username,
                "first_name": me.first_name,
                "can_join_groups": me.can_join_groups,
                "can_read_all_group_messages": me.can_read_all_group_messages
            }

            # Update scanner credentials
            self.scanner.update_settings(
                api_key=config.virustotal_api_key,
                cache_ttl=config.cache_ttl_seconds
            )

            # Recreate dispatcher
            self.dp = Dispatcher()
            setup_handlers(router, self.scanner, self.config_getter)
            self.dp.include_router(router)

            # Start polling as a background task
            self._polling_task = asyncio.create_task(self._run_polling())
            self.status = "RUNNING"
            logger.info(f"Telegram bot @{me.username} successfully started.")
            return True

        except Exception as e:
            self.status = "ERROR"
            self.error_message = str(e)
            logger.error(f"Failed to start Telegram Bot: {e}")
            return False

    async def _run_polling(self):
        try:
            # Delete any webhooks before polling
            await self.bot.delete_webhook(drop_pending_updates=True)
            await self.dp.start_polling(self.bot)
        except asyncio.CancelledError:
            logger.info("Bot polling loop cancelled.")
        except Exception as e:
            self.status = "ERROR"
            self.error_message = str(e)
            logger.error(f"Exception during bot polling: {e}")

    async def stop(self):
        self.status = "STOPPED"
        if self._polling_task and not self._polling_task.done():
            self._polling_task.cancel()
            try:
                await self._polling_task
            except asyncio.CancelledError:
                pass
            self._polling_task = None

        if self.dp:
            await self.dp.stop_polling()

        if self.bot and self.bot.session:
            await self.bot.session.close()

        logger.info("Bot stopped successfully.")

    async def restart(self) -> bool:
        await self.stop()
        return await self.start()

    async def test_telegram_token(self, token: str) -> dict:
        try:
            test_bot = Bot(token=token)
            me = await test_bot.get_me()
            await test_bot.session.close()
            return {
                "valid": True,
                "username": me.username,
                "first_name": me.first_name,
                "can_read_all_group_messages": me.can_read_all_group_messages
            }
        except Exception as e:
            return {"valid": False, "error": str(e)}

    def get_status(self) -> dict:
        if self._polling_task and not self._polling_task.done():
            self.status = "RUNNING"
        elif self.status == "RUNNING" and (self._polling_task is None or self._polling_task.done()):
            self.status = "STOPPED"
        return {
            "status": self.status,
            "error_message": self.error_message,
            "bot_info": self.bot_info
        }
