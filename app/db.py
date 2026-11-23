import os
import aiosqlite
from pathlib import Path
from datetime import datetime

DATA_DIR = Path(os.getenv("DATA_DIR", "data"))
DB_FILE = DATA_DIR / "events.db"

async def init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scan_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,       -- 'FILE' or 'URL'
                target TEXT NOT NULL,           -- file name or URL
                target_hash TEXT,               -- SHA-256 for files, URL ID for URLs
                malicious_count INTEGER NOT NULL,
                suspicious_count INTEGER NOT NULL,
                verdict TEXT NOT NULL,          -- 'CLEAN', 'THREAT', 'UNKNOWN', 'ERROR'
                action_taken TEXT NOT NULL,     -- 'REPLY_ALERT', 'DELETE_AND_ALERT', 'REACT_ONLY', 'NONE'
                chat_title TEXT,
                sender TEXT
            )
        """)
        # Auto-migration: Ensure 'sender' column exists in pre-existing tables
        async with db.execute("PRAGMA table_info(scan_events)") as cursor:
            columns = [row[1] for row in await cursor.fetchall()]
            if "sender" not in columns:
                await db.execute("ALTER TABLE scan_events ADD COLUMN sender TEXT")
        await db.commit()

async def log_scan_event(
    event_type: str,
    target: str,
    target_hash: str,
    malicious: int,
    suspicious: int,
    verdict: str,
    action_taken: str,
    chat_title: str = "Private Chat",
    sender: str = "Unknown"
):
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            """
            INSERT INTO scan_events (
                timestamp, event_type, target, target_hash, malicious_count, 
                suspicious_count, verdict, action_taken, chat_title, sender
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                event_type,
                target,
                target_hash,
                malicious,
                suspicious,
                verdict,
                action_taken,
                chat_title,
                sender
            )
        )
        await db.commit()

async def get_recent_events(limit: int = 50):
    async with aiosqlite.connect(DB_FILE) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM scan_events ORDER BY id DESC LIMIT ?", (limit,)
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

async def get_stats():
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("SELECT COUNT(*) FROM scan_events") as cursor:
            total_scans = (await cursor.fetchone())[0]

        async with db.execute("SELECT COUNT(*) FROM scan_events WHERE verdict = 'THREAT'") as cursor:
            total_threats = (await cursor.fetchone())[0]

        async with db.execute("SELECT COUNT(*) FROM scan_events WHERE event_type = 'FILE'") as cursor:
            total_files = (await cursor.fetchone())[0]

        async with db.execute("SELECT COUNT(*) FROM scan_events WHERE event_type = 'URL'") as cursor:
            total_urls = (await cursor.fetchone())[0]

        return {
            "total_scans": total_scans,
            "total_threats": total_threats,
            "total_files": total_files,
            "total_urls": total_urls
        }
