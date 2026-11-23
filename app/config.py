import os
import json
from pathlib import Path
from pydantic import BaseModel, Field

DATA_DIR = Path(os.getenv("DATA_DIR", "data"))
CONFIG_FILE = DATA_DIR / "config.json"

class AppConfig(BaseModel):
    telegram_bot_token: str = Field(default="", description="Telegram Bot API Token from @BotFather")
    virustotal_api_key: str = Field(default="", description="VirusTotal API v3 Key")
    
    # Feature Flags
    scan_files: bool = Field(default=True, description="Enable automatic file scanning")
    scan_urls: bool = Field(default=True, description="Enable automatic URL scanning")
    
    # Security Policies
    malicious_threshold: int = Field(default=1, ge=1, le=70, description="Minimum engines flagging as malicious")
    suspicious_threshold: int = Field(default=2, ge=1, le=70, description="Minimum engines flagging as suspicious")
    threat_action: str = Field(default="REPLY_ALERT", description="REACT_ONLY, REPLY_ALERT, or DELETE_AND_ALERT")
    
    # Reactions (Standard Telegram Bot allowed emojis)
    clean_reaction: str = Field(default="👍", description="Reaction emoji for clean items")
    threat_reaction: str = Field(default="👎", description="Reaction emoji for threats")
    unknown_reaction: str = Field(default="🤷‍♂️", description="Reaction emoji for unknown items")
    
    # Operational Settings
    max_file_size_mb: int = Field(default=20, ge=1, le=50, description="Max file size in MB (Telegram default: 20MB)")
    cache_ttl_seconds: int = Field(default=86400, ge=60, description="Cache retention for threat intel verdicts")

    # Future Extensibility
    otx_api_key: str = Field(default="", description="AlienVault OTX API key (optional)")
    abuseipdb_api_key: str = Field(default="", description="AbuseIPDB API key (optional)")

def load_config() -> AppConfig:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return AppConfig(**data)
        except Exception as e:
            print(f"Error reading {CONFIG_FILE}: {e}. Falling back to defaults.")
            return AppConfig()
    else:
        # Create default config file if it does not exist
        default_cfg = AppConfig()
        save_config(default_cfg)
        return default_cfg

def save_config(config: AppConfig) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config.model_dump(), f, indent=4)
