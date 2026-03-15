"""Agent 1: CVE Extractor — parses CVEs and extracts structured threat intelligence."""

import asyncio
import json
import logging
import re

from langchain_core.messages import HumanMessage, SystemMessage

from backend.agents.state import ThreatAnalysisState
from backend.config import get_llm
from backend.ingestion.abusech_fetcher import fetch_threatfox_by_cve
from backend.ingestion.cisa_kev import is_in_kev
from backend.ingestion.nvd_fetcher import fetch_cve
from backend.ingestion.otx_fetcher import fetch_otx_pulse_by_cve

logger = logging.getLogger("backend.agents.cve_extractor")

SYSTEM_PROMPT = """You are a cybersecurity threat intelligence analyst. Your task is to analyze a CVE (Common Vulnerabilities and Exposures) entry and extract structured threat intelligence.

Given a CVE description and any enrichment data, extract the following information as a JSON object:

{
  "summary": "Brief 1-2 sentence summary of the vulnerability",
  "severity_assessment": "CRITICAL/HIGH/MEDIUM/LOW with justification",
  "attack_vector": "Network/Adjacent/Local/Physical",
  "attack_complexity": "Low/High",
  "privileges_required": "None/Low/High",
  "user_interaction": "None/Required",
  "affected_software": ["List of affected products/versions"],
  "cwe_category": "CWE-ID and name if identifiable",
  "vulnerability_type": "e.g., Remote Code Execution, SQL Injection, XSS, etc.",
  "potential_impact": "What an attacker could achieve",
  "iocs": ["Any indicators of compromise mentioned"],
  "key_risk_factors": ["List of key risk factors"],
  "exploitation_likelihood": "Active/Likely/Possible/Unlikely",
  "recommended_priority": "Immediate/High/Medium/Low"
}

Respond ONLY with the JSON object. No markdown formatting, no code fences."""


def cve_extractor_agent(state: ThreatAnalysisState) -> dict:
    """LangGraph node: Extract structured threat info from CVE data.

    Enriches with NVD API data if cve_id is provided.
    Uses Foundation-Sec-8B-Reasoning to analyze and extract structured fields.
    """
    cve_id = state.get("cve_id", "")
    cve_description = state.get("cve_description", "")

    # Enrich from NVD if we have a CVE ID
    nvd_data = {}
    if cve_id and cve_id.startswith("CVE-"):
        try:
            nvd_data = asyncio.get_event_loop().run_until_complete(fetch_cve(cve_id))
        except RuntimeError:
            # No event loop running, create one
            nvd_data = asyncio.run(fetch_cve(cve_id))

        if "error" not in nvd_data:
            if not cve_description:
                cve_description = nvd_data.get("description", "")

    # Check CISA KEV
    in_kev = is_in_kev(cve_id) if cve_id else False

    # Build the analysis prompt
    enrichment_context = ""
    if nvd_data and "error" not in nvd_data:
        enrichment_context = (
            f"\n\nNVD Enrichment Data:\n"
            f"- CVSS Score: {nvd_data.get('cvss_score', 'N/A')}\n"
            f"- CVSS Vector: {nvd_data.get('cvss_vector', 'N/A')}\n"
            f"- Severity: {nvd_data.get('severity', 'N/A')}\n"
            f"- CWEs: {', '.join(nvd_data.get('cwes', []))}\n"
            f"- Published: {nvd_data.get('published', 'N/A')}\n"
            f"- Affected Products: {', '.join(nvd_data.get('affected_products', [])[:5])}"
        )

    if in_kev:
        enrichment_context += (
            "\n- CISA KEV: YES — This vulnerability is actively exploited in the wild."
        )

    # Enrich with AlienVault OTX
    otx_pulses: list[dict] = []
    otx_iocs: list[dict] = []
    if cve_id and cve_id.startswith("CVE-"):
        try:
            otx_pulses = asyncio.get_event_loop().run_until_complete(fetch_otx_pulse_by_cve(cve_id))
        except RuntimeError:
            otx_pulses = asyncio.run(fetch_otx_pulse_by_cve(cve_id))
        for pulse in otx_pulses:
            otx_iocs.extend(pulse.get("iocs", []))

    if otx_pulses:
        enrichment_context += (
            f"\n- OTX Pulses: {len(otx_pulses)} related threat pulses found"
            f"\n- OTX IOCs: {len(otx_iocs)} indicators of compromise"
            f"\n- IOC Types: {', '.join(set(i['type'] for i in otx_iocs[:50]))}"
        )

    # Enrich with abuse.ch ThreatFox
    threatfox_iocs: list[dict] = []
    if cve_id and cve_id.startswith("CVE-"):
        try:
            threatfox_iocs = asyncio.get_event_loop().run_until_complete(
                fetch_threatfox_by_cve(cve_id)
            )
        except RuntimeError:
            threatfox_iocs = asyncio.run(fetch_threatfox_by_cve(cve_id))

    if threatfox_iocs:
        malware_families = set(i.get("malware", "") for i in threatfox_iocs if i.get("malware"))
        enrichment_context += f"\n- ThreatFox IOCs: {len(threatfox_iocs)} indicators found"
        if malware_families:
            enrichment_context += f"\n- Malware families: {', '.join(malware_families)}"

    user_prompt = (
        f"Analyze this CVE:\n\nCVE ID: {cve_id}\nDescription: {cve_description}{enrichment_context}"
    )

    # Call LLM
    llm = get_llm()
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=user_prompt),
    ]
    response = llm.invoke(messages)
    raw_output = response.content

    # Parse JSON from response (handle thinking tags and markdown fences)
    extracted = _parse_llm_json(raw_output)

    # Merge NVD data into extracted info
    if nvd_data and "error" not in nvd_data:
        extracted["nvd_cvss_score"] = nvd_data.get("cvss_score")
        extracted["nvd_severity"] = nvd_data.get("severity")
        extracted["nvd_cwes"] = nvd_data.get("cwes", [])
        extracted["nvd_references"] = nvd_data.get("references", [])[:5]
        extracted["nvd_published"] = nvd_data.get("published")

    extracted["cisa_kev"] = in_kev
    extracted["cve_id"] = cve_id
    extracted["otx_pulses"] = otx_pulses[:10]
    extracted["otx_iocs"] = otx_iocs[:50]
    extracted["otx_pulse_count"] = len(otx_pulses)
    extracted["threatfox_iocs"] = threatfox_iocs[:30]
    extracted["threatfox_ioc_count"] = len(threatfox_iocs)

    return {
        "extracted_info": extracted,
        "cve_description": cve_description,
        "messages": [f"[Agent 1: CVE Extractor] Analyzed {cve_id or 'threat description'}"],
    }


def _parse_llm_json(text: str) -> dict:
    """Extract JSON from LLM output, handling <think> tags and code fences."""
    # Remove <think>...</think> blocks (Foundation-Sec reasoning traces)
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    # Handle missing opening <think> tag — strip everything before </think>
    if "</think>" in text:
        text = text.split("</think>")[-1]

    # Remove markdown code fences
    text = re.sub(r"```json\s*", "", text)
    text = re.sub(r"```\s*", "", text)

    # Find JSON object
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    return {"raw_output": text.strip(), "parse_error": True}
