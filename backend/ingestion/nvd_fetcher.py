"""NVD API 2.0 client for fetching CVE data."""

import asyncio
import sys

import httpx

from backend.config import get_settings


async def fetch_cve(cve_id: str) -> dict:
    """Fetch a single CVE from NVD API 2.0.

    Returns a dict with: cve_id, description, cvss_score, cvss_vector,
    severity, cwes, references, published, last_modified, affected_products.
    """
    from backend.cache import cve_cache

    if cve_id in cve_cache:
        return cve_cache[cve_id]

    settings = get_settings()
    headers = {}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    url = f"{settings.nvd_base_url}?cveId={cve_id}"

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {"error": f"CVE {cve_id} not found"}

    cve = vulns[0]["cve"]
    result = _parse_cve(cve)
    cve_cache[cve_id] = result
    return result


async def fetch_recent_cves(days: int = 7, max_results: int = 20) -> list[dict]:
    """Fetch recently modified CVEs from NVD."""
    from datetime import datetime, timedelta, timezone

    settings = get_settings()
    headers = {}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    params = {
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": str(max_results),
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(settings.nvd_base_url, params=params, headers=headers)
        resp.raise_for_status()
        data = resp.json()

    return [_parse_cve(v["cve"]) for v in data.get("vulnerabilities", [])]


def _parse_cve(cve: dict) -> dict:
    """Parse raw NVD CVE JSON into a clean dict."""
    cve_id = cve.get("id", "")

    # Description (prefer English)
    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        descriptions[0]["value"] if descriptions else "",
    )

    # CVSS v3.1 metrics
    cvss_score = None
    cvss_vector = None
    severity = "UNKNOWN"
    metrics = cve.get("metrics", {})
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            cvss_data = metrics[key][0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            severity = cvss_data.get("baseSeverity", "UNKNOWN")
            break

    # CWEs
    cwes = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            if desc.get("value", "").startswith("CWE-"):
                cwes.append(desc["value"])

    # References
    references = [
        {"url": ref.get("url"), "source": ref.get("source")}
        for ref in cve.get("references", [])[:10]
    ]

    # Affected products (CPE)
    affected_products = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    affected_products.append(match.get("criteria", ""))

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "severity": severity,
        "cwes": cwes,
        "references": references,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "affected_products": affected_products[:20],
    }


# CLI entry point
if __name__ == "__main__":
    import json

    cve_id = sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-44228"
    result = asyncio.run(fetch_cve(cve_id))
    print(json.dumps(result, indent=2))
