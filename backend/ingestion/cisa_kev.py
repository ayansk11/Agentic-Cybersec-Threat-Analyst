"""CISA Known Exploited Vulnerabilities catalog downloader."""

import asyncio
import json
from pathlib import Path

import httpx

from backend.config import get_settings

KEV_CACHE_PATH = Path("data/cisa_kev.json")


async def fetch_kev_catalog() -> list[dict]:
    """Download and parse the full CISA KEV catalog."""
    settings = get_settings()

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(settings.cisa_kev_url)
        resp.raise_for_status()
        data = resp.json()

    vulnerabilities = data.get("vulnerabilities", [])

    # Cache locally
    KEV_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    KEV_CACHE_PATH.write_text(json.dumps(data, indent=2))

    return [_parse_kev_entry(v) for v in vulnerabilities]


def load_cached_kev() -> list[dict]:
    """Load KEV catalog from local cache."""
    if not KEV_CACHE_PATH.exists():
        return []
    data = json.loads(KEV_CACHE_PATH.read_text())
    return [_parse_kev_entry(v) for v in data.get("vulnerabilities", [])]


def is_in_kev(cve_id: str) -> bool:
    """Check if a CVE is in the CISA KEV catalog (uses cache)."""
    entries = load_cached_kev()
    return any(e["cve_id"] == cve_id for e in entries)


def _parse_kev_entry(entry: dict) -> dict:
    return {
        "cve_id": entry.get("cveID", ""),
        "vendor": entry.get("vendorProject", ""),
        "product": entry.get("product", ""),
        "vulnerability_name": entry.get("vulnerabilityName", ""),
        "date_added": entry.get("dateAdded", ""),
        "due_date": entry.get("dueDate", ""),
        "required_action": entry.get("requiredAction", ""),
        "known_ransomware": entry.get("knownRansomwareCampaignUse", "Unknown"),
    }


if __name__ == "__main__":
    catalog = asyncio.run(fetch_kev_catalog())
    print(f"Downloaded {len(catalog)} KEV entries")
    if catalog:
        print(json.dumps(catalog[0], indent=2))
