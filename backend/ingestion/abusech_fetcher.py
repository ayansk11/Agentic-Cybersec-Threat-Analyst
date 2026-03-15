"""abuse.ch ThreatFox API client for fetching IOCs."""

import asyncio
import logging
import sys

import httpx

from backend.config import get_settings

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"

logger = logging.getLogger("backend.threatfox")


def _headers() -> dict[str, str]:
    """Build request headers, including API-KEY if configured."""
    settings = get_settings()
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if settings.threatfox_api_key:
        headers["API-KEY"] = settings.threatfox_api_key
    return headers


async def fetch_threatfox_by_cve(cve_id: str) -> list[dict]:
    """Search ThreatFox for IOCs associated with a CVE.

    Returns list of parsed IOC dicts.
    """
    from backend.cache import cve_cache

    cache_key = f"threatfox:{cve_id}"
    if cache_key in cve_cache:
        return cve_cache[cache_key]

    body = {"query": "search_ioc", "search_term": cve_id}

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(THREATFOX_API_URL, json=body, headers=_headers())
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, httpx.TimeoutException) as exc:
        logger.warning("ThreatFox CVE lookup failed: %s", exc)
        return []

    if data.get("query_status") != "ok":
        return []

    entries = data.get("data", [])
    if not isinstance(entries, list):
        return []

    result = [_parse_threatfox_ioc(e) for e in entries[:50]]
    cve_cache[cache_key] = result
    return result


async def fetch_threatfox_recent(days: int = 7, limit: int = 50) -> list[dict]:
    """Fetch recent IOCs from ThreatFox.

    Returns list of parsed IOC dicts.
    """
    body = {"query": "get_iocs", "days": min(days, 7)}

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(THREATFOX_API_URL, json=body, headers=_headers())
            if resp.status_code == 401:
                logger.warning("ThreatFox API returned 401 — set THREATFOX_API_KEY in .env")
                return []
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, httpx.TimeoutException) as exc:
        logger.warning("ThreatFox recent feed failed: %s", exc)
        return []

    if data.get("query_status") != "ok":
        return []

    entries = data.get("data", [])
    if not isinstance(entries, list):
        return []

    return [_parse_threatfox_ioc(e) for e in entries[:limit]]


def _parse_threatfox_ioc(entry: dict) -> dict:
    """Parse a ThreatFox IOC entry into a clean dict."""
    return {
        "ioc_id": entry.get("id", 0),
        "ioc_type": entry.get("ioc_type", ""),
        "ioc_value": entry.get("ioc", ""),
        "threat_type": entry.get("threat_type", ""),
        "malware": entry.get("malware_printable", "") or "",
        "confidence_level": entry.get("confidence_level", 0) or 0,
        "first_seen": entry.get("first_seen_utc"),
        "tags": entry.get("tags") or [],
    }


# CLI entry point
if __name__ == "__main__":
    import json

    cve_id = sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-44228"
    result = asyncio.run(fetch_threatfox_by_cve(cve_id))
    print(f"Found {len(result)} IOCs")
    print(json.dumps(result[:5], indent=2))
