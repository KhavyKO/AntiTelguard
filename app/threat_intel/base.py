from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from pydantic import BaseModel

class ScanResult(BaseModel):
    provider: str
    target: str
    target_hash: Optional[str] = None
    status: str       # 'found', 'not_found', 'submitted', 'error'
    verdict: str      # 'CLEAN', 'THREAT', 'UNKNOWN', 'ERROR'
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    permalink: Optional[str] = None
    error_message: Optional[str] = None
    raw_stats: Optional[Dict[str, Any]] = None

class BaseScanner(ABC):
    @abstractmethod
    async def scan_file_hash(self, sha256_hash: str) -> ScanResult:
        pass

    @abstractmethod
    async def scan_url(self, target_url: str) -> ScanResult:
        pass

    @abstractmethod
    async def test_connection(self) -> dict:
        pass
