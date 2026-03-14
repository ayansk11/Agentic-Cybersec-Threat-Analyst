"""AlienVault OTX API client for fetching threat pulses and IOCs."""

import asyncio
import sys

import httpx

from backend.config import get_settings


async def fetch_otx_pulse_by_cve(cve_id: str) -> list[dict]:
    """Fetch OTX pulses related to a specific CVE.

    Returns a list of dicts with: pulse_id, name, description,
    created, tags, adversary, iocs.
    """
    from backend.cache import cve_cache

    cache_key = f"otx:{cve_id}"
    if cache_key in cve_cache:
        return cve_cache[cache_key]

    settings = get_settings()
    if not settings.otx_api_key:
        return []

    headers = {"X-OTX-API-KEY": settings.otx_api_key}
    url = f"{settings.otx_base_url}/indicators/cve/{cve_id}/general"

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 404:
                return []
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, httpx.TimeoutException):
        return []

    pulses = data.get("pulse_info", {}).get("pulses", [])
    result = [_parse_pulse(p) for p in pulses[:20]]
    cve_cache[cache_key] = result
    return result


async def fetch_otx_recent_pulses(days: int = 7, limit: int = 20) -> list[dict]:
    """Fetch recent OTX pulses from subscribed feed.

    Requires an API key. Returns list of parsed pulse dicts.
    """
    from datetime import datetime, timedelta, timezone

    settings = get_settings()
    if not settings.otx_api_key:
        return []

    headers = {"X-OTX-API-KEY": settings.otx_api_key}
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    url = f"{settings.otx_base_url}/pulses/subscribed"
    params = {"modified_since": since, "limit": str(limit)}

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, httpx.TimeoutException):
        return []

    return [_parse_pulse(p) for p in data.get("results", [])[:limit]]


def _parse_pulse(pulse: dict) -> dict:
    """Parse raw OTX pulse JSON into a clean dict."""
    indicators = pulse.get("indicators", [])
    iocs = [
        {
            "type": ind.get("type", ""),
            "indicator": ind.get("indicator", ""),
            "description": ind.get("description", ""),
        }
        for ind in indicators[:50]
    ]

    return {
        "pulse_id": pulse.get("id", ""),
        "name": pulse.get("name", ""),
        "description": pulse.get("description", "")[:500],
        "created": pulse.get("created"),
        "tags": pulse.get("tags", [])[:20],
        "adversary": pulse.get("adversary", "") or "",
        "ioc_count": len(indicators),
        "iocs": iocs,
    }


# CLI entry point
if __name__ == "__main__":
    import json

    cve_id = sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-44228"
    result = asyncio.run(fetch_otx_pulse_by_cve(cve_id))
    print(json.dumps(result, indent=2))
