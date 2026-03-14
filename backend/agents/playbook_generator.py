"""Agent 3: Playbook Generator — generates NIST SP 800-61 playbooks and Sigma detection rules."""

import logging
import re

from langchain_core.messages import HumanMessage, SystemMessage

from backend.agents.state import ThreatAnalysisState
from backend.config import get_llm

logger = logging.getLogger("backend.agents.playbook_generator")

PLAYBOOK_SYSTEM_PROMPT = """You are a senior incident response analyst. Generate a structured incident response playbook following the NIST SP 800-61 framework.

Output the playbook in markdown with exactly these sections:

# Incident Response Playbook: {CVE ID}

## 1. Incident Overview
Brief summary: CVE ID, severity, vulnerability type, affected systems, and exploitation status.

## 2. Detection & Analysis
- Indicators of compromise (IOCs) to monitor
- Relevant log sources and SIEM queries
- Network and host-based detection methods
- Triage criteria and severity classification

## 3. Containment
### Short-Term Containment
- Immediate actions to limit blast radius (network isolation, blocking IPs/ports, disabling services)
### Long-Term Containment
- Sustained measures while preparing eradication (firewall rules, WAF rules, access restrictions)

## 4. Eradication
- Patching and update procedures
- Configuration hardening steps
- Removal of attacker artifacts (backdoors, persistence mechanisms)
- Verification that the vulnerability is remediated

## 5. Recovery
- System restoration procedures
- Validation and testing steps
- Monitoring for re-compromise
- Phased return to production

## 6. Lessons Learned
- Root cause analysis points
- Process improvements
- Detection gap remediation
- Recommendations for preventing recurrence

Be specific and actionable. Reference the actual CVE, affected software, and ATT&CK techniques provided. Do NOT include any JSON or code fences — output only the markdown playbook."""

SIGMA_SYSTEM_PROMPT = """You are a detection engineer specializing in Sigma rules. Generate a single valid Sigma detection rule in YAML format.

The rule must follow the Sigma specification with these fields:
- title: Descriptive title referencing the CVE or attack
- id: A UUID (generate one)
- status: experimental
- description: What the rule detects, referencing the CVE
- references: List with relevant URLs
- author: Automated Threat Analyst
- date: 2024/01/01
- tags: ATT&CK technique tags in attack.tXXXX format (e.g., attack.t1190, attack.initial_access)
- logsource: Appropriate category/product/service for the attack vector
- detection: Selection criteria and condition
- fields: Relevant fields to extract
- falsepositives: Known false positive scenarios
- level: critical/high/medium/low matching the vulnerability severity

Output ONLY the raw YAML content. No markdown fences, no explanations, no commentary."""


def _strip_thinking(text: str) -> str:
    """Remove <think>...</think> reasoning traces from LLM output."""
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def _extract_markdown(text: str) -> str:
    """Extract markdown playbook from LLM output."""
    text = _strip_thinking(text)
    # Remove code fences if the model wrapped the whole thing
    text = re.sub(r"^```(?:markdown)?\s*\n?", "", text)
    text = re.sub(r"\n?```\s*$", "", text)
    return text.strip()


def _extract_yaml(text: str) -> str:
    """Extract YAML Sigma rule from LLM output."""
    text = _strip_thinking(text)

    # Try extracting from ```yaml ... ``` fences
    yaml_match = re.search(r"```yaml\s*\n(.*?)```", text, re.DOTALL)
    if yaml_match:
        return yaml_match.group(1).strip()

    # Try extracting from generic ``` ... ``` fences
    fence_match = re.search(r"```\s*\n(.*?)```", text, re.DOTALL)
    if fence_match:
        return fence_match.group(1).strip()

    # No fences — return raw output (should already be YAML)
    return text.strip()


def _format_techniques_summary(techniques: list[dict]) -> str:
    """Format ATT&CK techniques into a readable summary for the LLM prompt."""
    if not techniques:
        return "No ATT&CK techniques were identified."

    lines = []
    for t in techniques:
        tactics = ", ".join(t.get("tactics", []))
        confidence = t.get("confidence", "N/A")
        lines.append(
            f"- {t.get('technique_id', '?')} {t.get('name', '?')} "
            f"(Tactics: {tactics}, Confidence: {confidence})"
        )
    return "\n".join(lines)


def _build_threat_context(state: ThreatAnalysisState) -> str:
    """Build a unified threat context string from all upstream agent outputs."""
    extracted = state.get("extracted_info", {})
    techniques = state.get("attack_techniques", [])
    cve_id = state.get("cve_id", "")
    cve_description = state.get("cve_description", "")

    parts = [
        f"CVE ID: {cve_id}",
        f"Description: {cve_description}",
        f"Vulnerability Type: {extracted.get('vulnerability_type', 'N/A')}",
        f"Attack Vector: {extracted.get('attack_vector', 'N/A')}",
        f"Severity: {extracted.get('severity_assessment', extracted.get('nvd_severity', 'N/A'))}",
        f"CVSS Score: {extracted.get('nvd_cvss_score', 'N/A')}",
        f"CWE: {extracted.get('cwe_category', 'N/A')}",
        f"Potential Impact: {extracted.get('potential_impact', 'N/A')}",
        f"Affected Software: {', '.join(extracted.get('affected_software', [])) or 'N/A'}",
        f"Exploitation Likelihood: {extracted.get('exploitation_likelihood', 'N/A')}",
        f"CISA KEV: {'Yes' if extracted.get('cisa_kev') else 'No'}",
        f"\nMapped ATT&CK Techniques:\n{_format_techniques_summary(techniques)}",
    ]
    return "\n".join(parts)


def playbook_generator_agent(state: ThreatAnalysisState) -> dict:
    """LangGraph node: Generate response playbook and Sigma detection rule.

    1. Synthesizes extracted_info + attack_techniques into threat context
    2. Generates NIST SP 800-61 structured playbook via LLM
    3. Generates Sigma YAML detection rule via LLM
    4. Returns both outputs
    """
    cve_id = state.get("cve_id", "")
    threat_context = _build_threat_context(state)
    llm = get_llm()

    # --- LLM Call 1: Generate Playbook ---
    playbook = ""
    try:
        playbook_response = llm.invoke(
            [
                SystemMessage(content=PLAYBOOK_SYSTEM_PROMPT),
                HumanMessage(
                    content=f"Generate an incident response playbook for the following threat:\n\n"
                    f"{threat_context}"
                ),
            ]
        )
        playbook = _extract_markdown(playbook_response.content)
    except Exception as e:
        logger.exception("Playbook generation failed for %s", cve_id)
        playbook = f"# Playbook Generation Failed\n\nError: {e}"

    # --- LLM Call 2: Generate Sigma Rule ---
    sigma_rule = ""
    try:
        techniques = state.get("attack_techniques", [])
        technique_tags = "\n".join(
            f"  - attack.{t.get('technique_id', '').lower()}"
            for t in techniques
            if t.get("technique_id")
        )
        tactic_tags = "\n".join(
            f"  - attack.{tactic.replace('-', '_')}"
            for t in techniques
            for tactic in t.get("tactics", [])
        )
        all_tags = technique_tags
        if tactic_tags:
            all_tags = f"{technique_tags}\n{tactic_tags}" if technique_tags else tactic_tags

        sigma_response = llm.invoke(
            [
                SystemMessage(content=SIGMA_SYSTEM_PROMPT),
                HumanMessage(
                    content=f"Generate a Sigma detection rule for the following threat:\n\n"
                    f"{threat_context}\n\n"
                    f"Use these ATT&CK tags in the rule:\n{all_tags or '  # No ATT&CK techniques identified'}"
                ),
            ]
        )
        sigma_rule = _extract_yaml(sigma_response.content)
    except Exception as e:
        logger.exception("Sigma rule generation failed for %s", cve_id)
        sigma_rule = f"# Sigma rule generation failed: {e}"

    outputs_generated = []
    if playbook and not playbook.startswith("# Playbook Generation Failed"):
        outputs_generated.append("playbook")
    if sigma_rule and not sigma_rule.startswith("# Sigma rule generation failed"):
        outputs_generated.append("Sigma rule")

    summary = " + ".join(outputs_generated) if outputs_generated else "nothing (generation failed)"

    return {
        "response_playbook": playbook,
        "sigma_rule": sigma_rule,
        "messages": [
            f"[Agent 3: Playbook Generator] Generated {summary} for "
            f"{cve_id or 'threat description'}"
        ],
    }
