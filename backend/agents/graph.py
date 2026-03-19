"""LangGraph StateGraph definition for the three-agent threat analysis pipeline."""

import logging

from langgraph.graph import END, START, StateGraph

from backend.agents.attack_classifier import attack_classifier_agent
from backend.agents.cve_extractor import cve_extractor_agent
from backend.agents.playbook_generator import playbook_generator_agent
from backend.agents.state import ThreatAnalysisState
from backend.guardrails import validate_output

logger = logging.getLogger("backend.agents")


def output_guardrail_node(state: ThreatAnalysisState) -> dict:
    """Validate pipeline outputs for quality and safety."""
    issues = validate_output(
        playbook=state.get("response_playbook", ""),
        sigma_rule=state.get("sigma_rule", ""),
        techniques=state.get("attack_techniques", []),
    )
    return {"guardrail_issues": issues}


# Build the pipeline: CVE Extractor → ATT&CK Classifier → Playbook Generator → Output Guardrail
workflow = StateGraph(ThreatAnalysisState)

workflow.add_node("cve_extractor", cve_extractor_agent)
workflow.add_node("attack_classifier", attack_classifier_agent)
workflow.add_node("playbook_generator", playbook_generator_agent)
workflow.add_node("output_guardrail", output_guardrail_node)

workflow.add_edge(START, "cve_extractor")
workflow.add_edge("cve_extractor", "attack_classifier")
workflow.add_edge("attack_classifier", "playbook_generator")
workflow.add_edge("playbook_generator", "output_guardrail")
workflow.add_edge("output_guardrail", END)

graph = workflow.compile()
