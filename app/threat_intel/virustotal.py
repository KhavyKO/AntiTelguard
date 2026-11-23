import base64
import logging
import httpx
from cachetools import TTLCache
from typing import Optional
from .base import BaseScanner, ScanResult

logger = logging.getLogger(__name__)

class VirusTotalScanner(BaseScanner):
    def __init__(self, api_key: str, cache_ttl: int = 86400):
        self.api_key = api_key
        self.cache = TTLCache(maxsize=3000, ttl=cache_ttl)
        self.base_url = "https://www.virustotal.com/api/v3"

    def update_settings(self, api_key: str, cache_ttl: int = 86400):
        self.api_key = api_key
        # Preserve cache if possible, or reset if TTL changes significantly
        if self.cache.ttl != cache_ttl:
            self.cache = TTLCache(maxsize=3000, ttl=cache_ttl)

    async def test_connection(self) -> dict:
        key = (self.api_key or "").strip()
        if not key:
            return {"valid": False, "error": "API key cannot be empty."}

        headers = {"x-apikey": key}
        async with httpx.AsyncClient(timeout=12.0) as client:
            try:
                # Method 1: Check overall quotas with api key as user ID (does not consume API quota)
                res = await client.get(f"{self.base_url}/users/{key}/overall_quotas", headers=headers)
                if res.status_code == 200:
                    return {"valid": True}
                elif res.status_code in (401, 403):
                    return {"valid": False, "error": "Invalid VirusTotal API key (HTTP 401 Unauthorized)."}

                # Method 2: Fallback query on well-known standard test hash (EICAR)
                test_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                res = await client.get(f"{self.base_url}/files/{test_hash}", headers=headers)
                if res.status_code == 200:
                    return {"valid": True}
                elif res.status_code in (401, 403):
                    return {"valid": False, "error": "Invalid VirusTotal API key (HTTP 401 Unauthorized)."}
                else:
                    return {"valid": False, "error": f"VirusTotal responded with HTTP {res.status_code}"}
            except Exception as e:
                logger.error(f"VirusTotal test_connection failed: {e}")
                return {"valid": False, "error": f"Connection error: {str(e)}"}

    async def scan_file_hash(self, sha256_hash: str) -> ScanResult:
        if not self.api_key:
            return ScanResult(
                provider="VirusTotal",
                target=sha256_hash,
                target_hash=sha256_hash,
                status="error",
                verdict="ERROR",
                error_message="VirusTotal API key not configured."
            )

        cache_key = f"file:{sha256_hash}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        headers = {"x-apikey": self.api_key}
        endpoint = f"{self.base_url}/files/{sha256_hash}"

        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                res = await client.get(endpoint, headers=headers)
                if res.status_code == 200:
                    data = res.json()["data"]["attributes"]
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    verdict = "THREAT" if (malicious > 0 or suspicious >= 2) else "CLEAN"

                    result = ScanResult(
                        provider="VirusTotal",
                        target=sha256_hash,
                        target_hash=sha256_hash,
                        status="found",
                        verdict=verdict,
                        malicious=malicious,
                        suspicious=suspicious,
                        harmless=stats.get("harmless", 0),
                        undetected=stats.get("undetected", 0),
                        permalink=f"https://www.virustotal.com/gui/file/{sha256_hash}",
                        raw_stats=stats
                    )
                elif res.status_code == 404:
                    result = ScanResult(
                        provider="VirusTotal",
                        target=sha256_hash,
                        target_hash=sha256_hash,
                        status="not_found",
                        verdict="UNKNOWN"
                    )
                else:
                    result = ScanResult(
                        provider="VirusTotal",
                        target=sha256_hash,
                        target_hash=sha256_hash,
                        status="error",
                        verdict="ERROR",
                        error_message=f"HTTP {res.status_code}: {res.text[:100]}"
                    )
            except Exception as e:
                logger.error(f"VT file scan error: {e}")
                result = ScanResult(
                    provider="VirusTotal",
                    target=sha256_hash,
                    target_hash=sha256_hash,
                    status="error",
                    verdict="ERROR",
                    error_message=str(e)
                )

        self.cache[cache_key] = result
        return result

    async def scan_url(self, target_url: str) -> ScanResult:
        if not self.api_key:
            return ScanResult(
                provider="VirusTotal",
                target=target_url,
                status="error",
                verdict="ERROR",
                error_message="VirusTotal API key not configured."
            )

        cache_key = f"url:{target_url}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        headers = {"x-apikey": self.api_key}
        endpoint = f"{self.base_url}/urls/{url_id}"

        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                res = await client.get(endpoint, headers=headers)
                if res.status_code == 200:
                    data = res.json()["data"]["attributes"]
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    verdict = "THREAT" if (malicious > 0 or suspicious >= 2) else "CLEAN"

                    result = ScanResult(
                        provider="VirusTotal",
                        target=target_url,
                        target_hash=url_id,
                        status="found",
                        verdict=verdict,
                        malicious=malicious,
                        suspicious=suspicious,
                        harmless=stats.get("harmless", 0),
                        undetected=stats.get("undetected", 0),
                        permalink=f"https://www.virustotal.com/gui/url/{url_id}",
                        raw_stats=stats
                    )
                elif res.status_code == 404:
                    # Submit URL for fresh scan
                    submit_res = await client.post(
                        f"{self.base_url}/urls",
                        headers=headers,
                        data={"url": target_url}
                    )
                    result = ScanResult(
                        provider="VirusTotal",
                        target=target_url,
                        target_hash=url_id,
                        status="submitted",
                        verdict="UNKNOWN",
                        permalink=f"https://www.virustotal.com/gui/url/{url_id}"
                    )
                else:
                    result = ScanResult(
                        provider="VirusTotal",
                        target=target_url,
                        target_hash=url_id,
                        status="error",
                        verdict="ERROR",
                        error_message=f"HTTP {res.status_code}: {res.text[:100]}"
                    )
            except Exception as e:
                logger.error(f"VT URL scan error: {e}")
                result = ScanResult(
                    provider="VirusTotal",
                    target=target_url,
                    target_hash=url_id,
                    status="error",
                    verdict="ERROR",
                    error_message=str(e)
                )

        self.cache[cache_key] = result
        return result
