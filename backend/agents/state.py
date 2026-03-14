"""Shared state definition for the LangGraph threat analysis pipeline."""

import operator
from typing import Annotated, TypedDict


class ThreatAnalysisState(TypedDict):
    """State passed between agents in the analysis pipeline.

    Agent 1 (CVE Extractor) populates: extracted_info
    Agent 2 (ATT&CK Classifier) populates: attack_techniques, rag_context
    Agent 3 (Playbook Generator) populates: response_playbook, sigma_rule
    """

    # Input
    cve_id: str
    cve_description: str

    # Agent 1 output
    extracted_info: dict

    # Agent 2 output
    attack_techniques: list[dict]
    rag_context: str

    # Agent 3 output
    response_playbook: str
    sigma_rule: str

    # Shared message log (append-only)
    messages: Annotated[list[str], operator.add]
