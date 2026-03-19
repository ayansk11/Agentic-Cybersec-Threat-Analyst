"""Agent 2: ATT&CK Classifier — maps threats to MITRE ATT&CK techniques via RAG."""

import json
import logging
import re

from langchain_core.messages import HumanMessage, SystemMessage

from backend.agents.state import ThreatAnalysisState
from backend.config import get_llm
from backend.rag.retriever import hybrid_search

logger = logging.getLogger("backend.agents.attack_classifier")

SYSTEM_PROMPT = """You are a cybersecurity threat intelligence analyst specializing in MITRE ATT&CK framework mapping.

Given a vulnerability description and a set of candidate ATT&CK techniques retrieved from the knowledge base, your task is to:
1. Determine which ATT&CK techniques are relevant to exploiting or leveraging this vulnerability
2. Assign a confidence score (0.0 to 1.0) to each relevant technique
3. Provide a brief rationale for each mapping

Only include techniques that are genuinely relevant. Not all candidate techniques will apply — typically 2-6 techniques are relevant for a given vulnerability.

Respond ONLY with a JSON object in this exact format (no markdown, no code fences):

{
  "techniques": [
    {
      "technique_id": "T1190",
      "name": "Exploit Public-Facing Application",
      "tactics": ["initial-access"],
      "confidence": 0.95,
      "rationale": "Brief explanation of why this technique applies"
    }
  ]
}"""


def _build_search_query(extracted: dict, cve_description: str) -> str:
    """Build a semantic search query from extracted threat intelligence."""
    parts = []

    if extracted.get("vulnerability_type"):
        parts.append(extracted["vulnerability_type"])
    if extracted.get("attack_vector"):
        parts.append(f"{extracted['attack_vector']} attack vector")
    if extracted.get("potential_impact"):
        parts.append(extracted["potential_impact"])
    if extracted.get("cwe_category"):
        parts.append(extracted["cwe_category"])
    if extracted.get("summary"):
        parts.append(extracted["summary"])

    if not parts:
        return cve_description or "unknown vulnerability"

    return ". ".join(parts)


def _format_rag_context(results: list[dict]) -> str:
    """Format hybrid search results into a numbered context block."""
    if not results:
        return "No ATT&CK techniques retrieved."

    blocks = []
    for i, r in enumerate(results, 1):
        tactics_str = ", ".join(r.get("tactics", []))
        blocks.append(
            f"[{i}] {r['technique_id']} — {r['name']}\n"
            f"    Tactics: {tactics_str}\n"
            f"    {r['text'][:500]}"
        )
    return "\n\n".join(blocks)


def _parse_techniques_json(text: str) -> list[dict]:
    """Extract technique classifications from LLM output."""
    # Strip <think>...</think> reasoning traces
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    # Handle missing opening <think> tag — strip everything before </think>
    if "</think>" in text:
        text = text.split("</think>")[-1]
    # Strip markdown code fences
    text = re.sub(r"```json\s*", "", text)
    text = re.sub(r"```\s*", "", text)

    # Try parsing as {techniques: [...]} wrapper
    obj_match = re.search(r"\{.*\}", text, re.DOTALL)
    if obj_match:
        try:
            parsed = json.loads(obj_match.group())
            if isinstance(parsed, dict) and "techniques" in parsed:
                return parsed["techniques"]
            # Maybe the object itself is a single technique
            if isinstance(parsed, dict) and "technique_id" in parsed:
                return [parsed]
        except json.JSONDecodeError:
            pass

    # Try parsing as bare array [...]
    arr_match = re.search(r"\[.*\]", text, re.DOTALL)
    if arr_match:
        try:
            parsed = json.loads(arr_match.group())
            if isinstance(parsed, list):
                return parsed
        except json.JSONDecodeError:
            pass

    return []


def attack_classifier_agent(state: ThreatAnalysisState) -> dict:
    """LangGraph node: Classify threat into ATT&CK techniques using RAG.

    1. Builds a query from extracted_info
    2. Runs hybrid search over MITRE ATT&CK collection in Qdrant
    3. Passes retrieved context + threat info to LLM for classification
    4. Returns structured technique mappings with confidence scores
    """
    extracted = state.get("extracted_info", {})
    cve_id = state.get("cve_id", "")
    cve_description = state.get("cve_description", "")

    # Step 1: Build search query
    query = _build_search_query(extracted, cve_description)

    # Step 2: Retrieve candidate techniques via RAG
    rag_results = []
    try:
        rag_results = hybrid_search(query, top_k=10)
    except Exception as e:
        logger.warning("Qdrant unavailable for %s: %s", cve_id, e)
        return {
            "attack_techniques": [],
            "rag_context": "",
            "messages": [f"[Agent 2: ATT&CK Classifier] Qdrant unavailable for {cve_id}: {e}"],
        }

    # Step 3: Format RAG context
    rag_context = _format_rag_context(rag_results)

    # Step 4: Build LLM prompt
    vuln_summary = (
        f"CVE ID: {cve_id}\n"
        f"Description: {cve_description}\n"
        f"Vulnerability Type: {extracted.get('vulnerability_type', 'N/A')}\n"
        f"Attack Vector: {extracted.get('attack_vector', 'N/A')}\n"
        f"Potential Impact: {extracted.get('potential_impact', 'N/A')}\n"
        f"CWE: {extracted.get('cwe_category', 'N/A')}\n"
        f"Severity: {extracted.get('severity_assessment', 'N/A')}"
    )

    user_prompt = (
        f"Analyze the following vulnerability and map it to relevant MITRE ATT&CK techniques.\n\n"
        f"## Vulnerability Information\n{vuln_summary}\n\n"
        f"## Candidate ATT&CK Techniques (from knowledge base)\n{rag_context}"
    )

    # Step 5: Call LLM
    llm = get_llm(state.get("model_id"))
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=user_prompt),
    ]
    response = llm.invoke(messages)

    # Step 6: Parse and sort techniques by confidence
    techniques = _parse_techniques_json(response.content)
    techniques.sort(key=lambda t: t.get("confidence", 0), reverse=True)

    return {
        "attack_techniques": techniques,
        "rag_context": rag_context,
        "messages": [
            f"[Agent 2: ATT&CK Classifier] Mapped {len(techniques)} ATT&CK "
            f"techniques for {cve_id or 'threat description'}"
        ],
    }
