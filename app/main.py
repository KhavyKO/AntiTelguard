import os
import logging
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from app.config import load_config, save_config, AppConfig
from app.db import init_db, get_recent_events, get_stats
from app.bot.manager import BotManager
from app.threat_intel.virustotal import VirusTotalScanner

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
INDEX_HTML = TEMPLATES_DIR / "index.html"

# State
current_config: AppConfig = load_config()
bot_manager = BotManager(
    config_getter=lambda: current_config,
    config_saver=lambda cfg: save_config(cfg)
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Initializing AntiTelguard Security Engine...")
    await init_db()
    await bot_manager.initialize()
    yield
    # Shutdown
    logger.info("Shutting down AntiTelguard...")
    await bot_manager.stop()

app = FastAPI(title="AntiTelguard Threat Intelligence Dashboard", lifespan=lifespan)
templates = Jinja2Templates(directory="app/templates")

# Request Models
class TokenTestRequest(BaseModel):
    token: str

class VTTestRequest(BaseModel):
    api_key: str

class BotActionRequest(BaseModel):
    action: str  # start, stop, restart

# --- Web UI Routes ---

@app.get("/", response_class=HTMLResponse)
async def index_page(request: Request):
    if INDEX_HTML.exists():
        content = INDEX_HTML.read_text(encoding="utf-8")
        return HTMLResponse(content=content)
    # Fallback to TemplateResponse with cross-version compatibility
    try:
        return templates.TemplateResponse(request=request, name="index.html")
    except TypeError:
        return templates.TemplateResponse("index.html", {"request": request})

# --- API Endpoints ---

@app.get("/api/status")
async def get_system_status():
    stats = await get_stats()
    bot_status = bot_manager.get_status()
    return {
        "bot": bot_status,
        "stats": stats,
        "config_ready": bool(current_config.telegram_bot_token and current_config.virustotal_api_key)
    }

@app.get("/api/config")
async def get_current_settings():
    return current_config.model_dump()

@app.post("/api/config")
async def update_settings(new_cfg: AppConfig):
    global current_config
    current_config = new_cfg
    save_config(current_config)

    # Hot restart bot with updated settings
    success = await bot_manager.restart()
    return {
        "status": "success",
        "bot_restarted": success,
        "bot_status": bot_manager.get_status()
    }

@app.post("/api/bot/action")
async def trigger_bot_action(req: BotActionRequest):
    if req.action == "start":
        res = await bot_manager.start()
    elif req.action == "stop":
        await bot_manager.stop()
        res = True
    elif req.action == "restart":
        res = await bot_manager.restart()
    else:
        raise HTTPException(status_code=400, detail="Invalid action")

    return {"status": "ok", "action": req.action, "result": res, "state": bot_manager.get_status()}

@app.post("/api/test/telegram")
async def test_telegram_token(req: TokenTestRequest):
    result = await bot_manager.test_telegram_token(req.token)
    return result

@app.post("/api/test/virustotal")
async def test_virustotal_key(req: VTTestRequest):
    scanner = VirusTotalScanner(api_key=req.api_key.strip())
    result = await scanner.test_connection()
    return result

@app.get("/api/events")
async def get_events(limit: int = 50):
    events = await get_recent_events(limit=limit)
    return {"events": events}

@app.get("/api/stats")
async def get_metrics():
    return await get_stats()
