"""End-to-end integration tests for the full LangGraph agent pipeline."""

import json
from unittest.mock import MagicMock, patch, AsyncMock


# ── Mock LLM responses ──────────────────────────────────────────────────

AGENT1_LLM_RESPONSE = json.dumps(
    {
        "summary": "Critical RCE in Apache Log4j2 via JNDI injection",
        "severity_assessment": "CRITICAL - actively exploited",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "affected_software": ["Apache Log4j2 2.0-beta9 through 2.15.0"],
        "cwe_category": "CWE-502 Deserialization of Untrusted Data",
        "vulnerability_type": "Remote Code Execution",
        "potential_impact": "Full system compromise via arbitrary code execution",
        "iocs": [],
        "key_risk_factors": ["No authentication required", "Network accessible"],
        "exploitation_likelihood": "Active",
        "recommended_priority": "Immediate",
    }
)

AGENT2_LLM_RESPONSE = json.dumps(
    {
        "techniques": [
            {
                "technique_id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactics": ["initial-access"],
                "confidence": 0.95,
                "rationale": "Log4Shell allows RCE via crafted JNDI lookups",
            },
            {
                "technique_id": "T1059",
                "name": "Command and Scripting Interpreter",
                "tactics": ["execution"],
                "confidence": 0.85,
                "rationale": "Post-exploitation command execution",
            },
        ]
    }
)

AGENT3_PLAYBOOK_RESPONSE = """# Incident Response Playbook: CVE-2021-44228

## 1. Incident Overview
Critical RCE in Apache Log4j2 via JNDI injection.

## 2. Detection & Analysis
- Monitor for JNDI lookup patterns in logs.

## 3. Containment
### Short-Term Containment
- Block outbound LDAP/RMI connections.

## 4. Eradication
- Upgrade Log4j to 2.17.1+.

## 5. Recovery
- Restore from known-good backups.

## 6. Lessons Learned
- Implement WAF rules for JNDI patterns."""

AGENT3_SIGMA_RESPONSE = """title: Log4Shell JNDI Exploitation Attempt
id: 12345678-1234-1234-1234-123456789abc
status: experimental
description: Detects Log4Shell exploitation attempts via JNDI lookup patterns
logsource:
    category: webserver
detection:
    selection:
        cs-uri|contains:
            - '${jndi:'
    condition: selection
level: critical"""


def _make_mock_llm(responses: list[str]) -> MagicMock:
    """Create a mock LLM that returns responses in sequence."""
    llm = MagicMock()
    side_effects = []
    for text in responses:
        resp = MagicMock()
        resp.content = text
        side_effects.append(resp)
    llm.invoke.side_effect = side_effects
    return llm


MOCK_NVD_DATA = {
    "cve_id": "CVE-2021-44228",
    "description": "Apache Log4j2 RCE vulnerability via JNDI",
    "cvss_score": 10.0,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "severity": "CRITICAL",
    "cwes": ["CWE-502"],
    "references": [],
    "published": "2021-12-10T10:15:00",
    "affected_products": ["cpe:2.3:a:apache:log4j:*"],
}

MOCK_RAG_RESULTS = [
    {
        "technique_id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactics": ["initial-access"],
        "text": "Adversaries may attempt to exploit a weakness in an Internet-facing host.",
    },
    {
        "technique_id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactics": ["execution"],
        "text": "Adversaries may abuse command and script interpreters to execute commands.",
    },
]


# ── Full Pipeline Test ──────────────────────────────────────────────────


class TestFullPipeline:
    """Test the complete 3-agent LangGraph pipeline with mocked externals."""

    @patch("backend.agents.cve_extractor.get_llm")
    @patch(
        "backend.agents.cve_extractor.fetch_threatfox_by_cve",
        new_callable=AsyncMock,
        return_value=[],
    )
    @patch(
        "backend.agents.cve_extractor.fetch_otx_pulse_by_cve",
        new_callable=AsyncMock,
        return_value=[],
    )
    @patch("backend.agents.cve_extractor.is_in_kev", return_value=True)
    @patch("backend.agents.cve_extractor.fetch_cve", new_callable=AsyncMock)
    @patch("backend.agents.attack_classifier.hybrid_search")
    @patch("backend.agents.attack_classifier.get_llm")
    @patch("backend.agents.playbook_generator.get_llm")
    def test_full_pipeline_produces_all_outputs(
        self,
        mock_pb_llm,
        mock_ac_llm,
        mock_rag,
        mock_fetch_cve,
        mock_kev,
        mock_otx,
        mock_tfox,
        mock_ce_llm,
    ):
        """Pipeline should produce extracted_info, techniques, playbook, and sigma rule."""
        # Setup mocks
        mock_fetch_cve.return_value = MOCK_NVD_DATA
        mock_rag.return_value = MOCK_RAG_RESULTS

        mock_ce_llm.return_value = _make_mock_llm([AGENT1_LLM_RESPONSE])
        mock_ac_llm.return_value = _make_mock_llm([AGENT2_LLM_RESPONSE])
        mock_pb_llm.return_value = _make_mock_llm([AGENT3_PLAYBOOK_RESPONSE, AGENT3_SIGMA_RESPONSE])

        from backend.agents.graph import graph

        initial_state = {
            "cve_id": "CVE-2021-44228",
            "cve_description": "",
            "extracted_info": {},
            "attack_techniques": [],
            "rag_context": "",
            "response_playbook": "",
            "sigma_rule": "",
            "messages": [],
        }

        result = graph.invoke(initial_state)

        # Agent 1 output
        assert result["extracted_info"]["cve_id"] == "CVE-2021-44228"
        assert result["extracted_info"]["cisa_kev"] is True
        assert result["extracted_info"]["nvd_cvss_score"] == 10.0
        assert "Remote Code Execution" in result["extracted_info"]["vulnerability_type"]

        # Agent 2 output
        assert len(result["attack_techniques"]) == 2
        assert result["attack_techniques"][0]["technique_id"] == "T1190"
        assert result["rag_context"]  # non-empty

        # Agent 3 output
        assert "Incident Response Playbook" in result["response_playbook"]
        assert "Log4Shell" in result["sigma_rule"]

        # All 3 agents logged messages
        assert len(result["messages"]) == 3
        assert "Agent 1" in result["messages"][0]
        assert "Agent 2" in result["messages"][1]
        assert "Agent 3" in result["messages"][2]


# ── API Integration Test ────────────────────────────────────────────────


class TestAnalyzeEndpoint:
    """Test the POST /api/analyze endpoint with mocked pipeline."""

    @patch("backend.api.routes.fire_webhook")
    @patch("backend.api.routes.save_analysis", new_callable=AsyncMock, return_value=1)
    @patch("backend.api.routes.graph")
    def test_analyze_returns_complete_response(
        self, mock_graph, mock_save, mock_webhook, test_client
    ):
        """Analyze endpoint should return structured response matching schema."""
        mock_graph.invoke.return_value = {
            "cve_id": "CVE-2021-44228",
            "cve_description": "Log4j RCE",
            "extracted_info": {
                "cve_id": "CVE-2021-44228",
                "summary": "Critical RCE",
                "severity_assessment": "CRITICAL",
                "nvd_severity": "CRITICAL",
                "nvd_cvss_score": 10.0,
            },
            "attack_techniques": [
                {
                    "technique_id": "T1190",
                    "name": "Exploit Public-Facing Application",
                    "tactics": ["initial-access"],
                    "confidence": 0.95,
                }
            ],
            "rag_context": "RAG context",
            "response_playbook": "# Playbook",
            "sigma_rule": "title: Test Rule",
            "messages": ["msg1", "msg2", "msg3"],
        }

        resp = test_client.post("/api/analyze", json={"cve_id": "CVE-2021-44228"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["cve_id"] == "CVE-2021-44228"
        assert data["response_playbook"] == "# Playbook"
        assert data["sigma_rule"] == "title: Test Rule"
        assert len(data["attack_techniques"]) == 1


# ── Error Handling Test ─────────────────────────────────────────────────


class TestPipelineErrorHandling:
    """Test that the pipeline handles errors gracefully."""

    @patch("backend.agents.cve_extractor.get_llm")
    @patch(
        "backend.agents.cve_extractor.fetch_threatfox_by_cve",
        new_callable=AsyncMock,
        return_value=[],
    )
    @patch(
        "backend.agents.cve_extractor.fetch_otx_pulse_by_cve",
        new_callable=AsyncMock,
        return_value=[],
    )
    @patch("backend.agents.cve_extractor.is_in_kev", return_value=False)
    @patch(
        "backend.agents.cve_extractor.fetch_cve",
        new_callable=AsyncMock,
        return_value={"error": "not found"},
    )
    @patch("backend.agents.attack_classifier.hybrid_search", side_effect=Exception("Qdrant down"))
    @patch("backend.agents.playbook_generator.get_llm")
    def test_pipeline_continues_on_qdrant_failure(
        self,
        mock_pb_llm,
        mock_rag,
        mock_fetch_cve,
        mock_kev,
        mock_otx,
        mock_tfox,
        mock_ce_llm,
    ):
        """If Qdrant is down, Agent 2 returns empty techniques and Agent 3 still runs."""
        mock_ce_llm.return_value = _make_mock_llm([AGENT1_LLM_RESPONSE])
        mock_pb_llm.return_value = _make_mock_llm([AGENT3_PLAYBOOK_RESPONSE, AGENT3_SIGMA_RESPONSE])

        from backend.agents.graph import graph

        result = graph.invoke(
            {
                "cve_id": "CVE-2024-0001",
                "cve_description": "Test vulnerability",
                "extracted_info": {},
                "attack_techniques": [],
                "rag_context": "",
                "response_playbook": "",
                "sigma_rule": "",
                "messages": [],
            }
        )

        # Agent 2 should report Qdrant failure but not crash
        assert result["attack_techniques"] == []
        assert "Qdrant unavailable" in result["messages"][1]

        # Agent 3 should still generate outputs
        assert result["response_playbook"]
        assert result["sigma_rule"]
