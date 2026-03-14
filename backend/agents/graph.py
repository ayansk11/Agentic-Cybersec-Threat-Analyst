"""LangGraph StateGraph definition for the three-agent threat analysis pipeline."""

from langgraph.graph import END, START, StateGraph

from backend.agents.attack_classifier import attack_classifier_agent
from backend.agents.cve_extractor import cve_extractor_agent
from backend.agents.playbook_generator import playbook_generator_agent
from backend.agents.state import ThreatAnalysisState

# Build the sequential pipeline: CVE Extractor → ATT&CK Classifier → Playbook Generator
workflow = StateGraph(ThreatAnalysisState)

workflow.add_node("cve_extractor", cve_extractor_agent)
workflow.add_node("attack_classifier", attack_classifier_agent)
workflow.add_node("playbook_generator", playbook_generator_agent)

workflow.add_edge(START, "cve_extractor")
workflow.add_edge("cve_extractor", "attack_classifier")
workflow.add_edge("attack_classifier", "playbook_generator")
workflow.add_edge("playbook_generator", END)

graph = workflow.compile()
