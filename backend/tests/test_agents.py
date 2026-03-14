"""Tests for the agent pipeline."""

import json
from unittest.mock import MagicMock, patch


from backend.agents.state import ThreatAnalysisState


# ── State tests ──────────────────────────────────────────────────────


def test_state_structure():
    """Verify ThreatAnalysisState has all required fields."""
    state: ThreatAnalysisState = {
        "cve_id": "CVE-2021-44228",
        "cve_description": "Apache Log4j2 RCE",
        "extracted_info": {},
        "attack_techniques": [],
        "rag_context": "",
        "response_playbook": "",
        "sigma_rule": "",
        "messages": [],
    }
    assert state["cve_id"] == "CVE-2021-44228"
    assert isinstance(state["messages"], list)


def test_state_allows_populated_fields(sample_extracted_info):
    """State accepts populated extracted_info."""
    state: ThreatAnalysisState = {
        "cve_id": "CVE-2021-44228",
        "cve_description": "test",
        "extracted_info": sample_extracted_info,
        "attack_techniques": [{"technique_id": "T1190", "name": "Exploit Public-Facing App"}],
        "rag_context": "context text",
        "response_playbook": "# Playbook",
        "sigma_rule": "title: test",
        "messages": ["msg1"],
    }
    assert state["extracted_info"]["nvd_cvss_score"] == 10.0
    assert len(state["attack_techniques"]) == 1


# ── CVE Extractor JSON parsing ────────────────────────────────────────


class TestParseLLMJson:
    """Tests for _parse_llm_json helper."""

    def test_clean_json(self):
        from backend.agents.cve_extractor import _parse_llm_json
        result = _parse_llm_json('{"summary": "test", "severity": "HIGH"}')
        assert result["summary"] == "test"

    def test_json_with_think_tags(self):
        from backend.agents.cve_extractor import _parse_llm_json
        result = _parse_llm_json(
            '<think>reasoning here</think>{"summary": "after thinking"}'
        )
        assert result["summary"] == "after thinking"

    def test_json_in_code_fence(self):
        from backend.agents.cve_extractor import _parse_llm_json
        result = _parse_llm_json('```json\n{"summary": "fenced"}\n```')
        assert result["summary"] == "fenced"

    def test_unparseable_returns_raw(self):
        from backend.agents.cve_extractor import _parse_llm_json
        result = _parse_llm_json("no json here")
        assert result.get("parse_error") is True
        assert "no json here" in result.get("raw_output", "")

    def test_json_with_nested_objects(self):
        from backend.agents.cve_extractor import _parse_llm_json
        data = '{"summary": "test", "affected_software": ["Apache Log4j 2.x"]}'
        result = _parse_llm_json(data)
        assert result["affected_software"] == ["Apache Log4j 2.x"]

    def test_json_with_think_and_fence(self):
        from backend.agents.cve_extractor import _parse_llm_json
        data = '<think>thinking...</think>\n```json\n{"summary": "both"}\n```'
        result = _parse_llm_json(data)
        assert result["summary"] == "both"

    def test_empty_string(self):
        from backend.agents.cve_extractor import _parse_llm_json
        result = _parse_llm_json("")
        assert result.get("parse_error") is True


# ── ATT&CK Classifier parsing ────────────────────────────────────────


class TestParseTechniquesJson:
    """Tests for _parse_techniques_json helper."""

    def test_wrapper_format(self):
        from backend.agents.attack_classifier import _parse_techniques_json
        data = '{"techniques": [{"technique_id": "T1190", "name": "Test", "confidence": 0.9}]}'
        result = _parse_techniques_json(data)
        assert len(result) == 1
        assert result[0]["technique_id"] == "T1190"

    def test_bare_array(self):
        from backend.agents.attack_classifier import _parse_techniques_json
        data = '[{"technique_id": "T1190", "confidence": 0.9}]'
        result = _parse_techniques_json(data)
        assert len(result) == 1

    def test_with_think_tags(self):
        from backend.agents.attack_classifier import _parse_techniques_json
        data = '<think>analysis</think>{"techniques": [{"technique_id": "T1059"}]}'
        result = _parse_techniques_json(data)
        assert result[0]["technique_id"] == "T1059"

    def test_with_code_fence(self):
        from backend.agents.attack_classifier import _parse_techniques_json
        data = '```json\n{"techniques": [{"technique_id": "T1190"}]}\n```'
        result = _parse_techniques_json(data)
        assert len(result) == 1

    def test_single_technique_object(self):
        from backend.agents.attack_classifier import _parse_techniques_json
        data = '{"technique_id": "T1190", "name": "Test"}'
        result = _parse_techniques_json(data)
        assert len(result) == 1

    def test_unparseable_returns_empty(self):
        from backend.agents.attack_classifier import _parse_techniques_json
        result = _parse_techniques_json("not valid json")
        assert result == []


# ── ATT&CK Classifier helpers ────────────────────────────────────────


class TestBuildSearchQuery:
    """Tests for _build_search_query helper."""

    def test_with_full_extracted(self, sample_extracted_info):
        from backend.agents.attack_classifier import _build_search_query
        query = _build_search_query(sample_extracted_info, "fallback")
        assert "Remote Code Execution" in query
        assert "Network" in query

    def test_with_empty_extracted(self):
        from backend.agents.attack_classifier import _build_search_query
        query = _build_search_query({}, "the fallback description")
        assert query == "the fallback description"

    def test_with_no_description_fallback(self):
        from backend.agents.attack_classifier import _build_search_query
        query = _build_search_query({}, "")
        assert query == "unknown vulnerability"


class TestFormatRagContext:
    """Tests for _format_rag_context helper."""

    def test_empty_results(self):
        from backend.agents.attack_classifier import _format_rag_context
        assert _format_rag_context([]) == "No ATT&CK techniques retrieved."

    def test_with_results(self):
        from backend.agents.attack_classifier import _format_rag_context
        results = [
            {"technique_id": "T1190", "name": "Exploit", "tactics": ["initial-access"], "text": "desc"},
        ]
        context = _format_rag_context(results)
        assert "T1190" in context
        assert "Exploit" in context
        assert "initial-access" in context


# ── Playbook Generator helpers ────────────────────────────────────────


class TestPlaybookHelpers:
    """Tests for playbook_generator helper functions."""

    def test_strip_thinking(self):
        from backend.agents.playbook_generator import _strip_thinking
        assert _strip_thinking("<think>thoughts</think>result") == "result"
        assert _strip_thinking("no thinking") == "no thinking"

    def test_extract_markdown(self):
        from backend.agents.playbook_generator import _extract_markdown
        md = "```markdown\n# Playbook\nContent\n```"
        assert _extract_markdown(md) == "# Playbook\nContent"

    def test_extract_markdown_no_fence(self):
        from backend.agents.playbook_generator import _extract_markdown
        assert _extract_markdown("# Playbook\nContent") == "# Playbook\nContent"

    def test_extract_yaml_from_fence(self):
        from backend.agents.playbook_generator import _extract_yaml
        yaml = "```yaml\ntitle: Test Rule\nstatus: experimental\n```"
        result = _extract_yaml(yaml)
        assert "title: Test Rule" in result

    def test_extract_yaml_no_fence(self):
        from backend.agents.playbook_generator import _extract_yaml
        raw = "title: Test Rule\nstatus: experimental"
        assert _extract_yaml(raw) == raw

    def test_extract_yaml_with_think(self):
        from backend.agents.playbook_generator import _extract_yaml
        text = "<think>reasoning</think>```yaml\ntitle: Rule\n```"
        result = _extract_yaml(text)
        assert "title: Rule" in result

    def test_format_techniques_summary_empty(self):
        from backend.agents.playbook_generator import _format_techniques_summary
        assert _format_techniques_summary([]) == "No ATT&CK techniques were identified."

    def test_format_techniques_summary(self):
        from backend.agents.playbook_generator import _format_techniques_summary
        techniques = [
            {"technique_id": "T1190", "name": "Exploit", "tactics": ["initial-access"], "confidence": 0.95},
        ]
        result = _format_techniques_summary(techniques)
        assert "T1190" in result
        assert "0.95" in result

    def test_build_threat_context(self, sample_state, sample_extracted_info):
        from backend.agents.playbook_generator import _build_threat_context
        sample_state["extracted_info"] = sample_extracted_info
        sample_state["attack_techniques"] = [
            {"technique_id": "T1190", "name": "Exploit", "tactics": ["initial-access"], "confidence": 0.95}
        ]
        context = _build_threat_context(sample_state)
        assert "CVE-2021-44228" in context
        assert "CRITICAL" in context
        assert "T1190" in context


# ── Agent node tests (mocked LLM + externals) ─────────────────────────


class TestCVEExtractorAgent:
    """Tests for the CVE extractor agent with mocked dependencies."""

    @patch("backend.agents.cve_extractor.fetch_threatfox_by_cve")
    @patch("backend.agents.cve_extractor.fetch_otx_pulse_by_cve")
    @patch("backend.agents.cve_extractor.is_in_kev")
    @patch("backend.agents.cve_extractor.fetch_cve")
    @patch("backend.agents.cve_extractor.get_llm")
    def test_agent_returns_extracted_info(
        self, mock_get_llm, mock_fetch_cve, mock_kev, mock_otx, mock_tfox, sample_state, mock_llm
    ):
        mock_get_llm.return_value = mock_llm
        mock_fetch_cve.return_value = {"error": "test skip"}
        mock_kev.return_value = False
        mock_otx.return_value = []
        mock_tfox.return_value = []

        from backend.agents.cve_extractor import cve_extractor_agent
        result = cve_extractor_agent(sample_state)

        assert "extracted_info" in result
        assert "messages" in result
        assert result["extracted_info"]["cve_id"] == "CVE-2021-44228"

    @patch("backend.agents.cve_extractor.fetch_threatfox_by_cve")
    @patch("backend.agents.cve_extractor.fetch_otx_pulse_by_cve")
    @patch("backend.agents.cve_extractor.is_in_kev")
    @patch("backend.agents.cve_extractor.fetch_cve")
    @patch("backend.agents.cve_extractor.get_llm")
    def test_agent_includes_kev_flag(
        self, mock_get_llm, mock_fetch_cve, mock_kev, mock_otx, mock_tfox, sample_state, mock_llm
    ):
        mock_get_llm.return_value = mock_llm
        mock_fetch_cve.return_value = {"error": "skip"}
        mock_kev.return_value = True
        mock_otx.return_value = []
        mock_tfox.return_value = []

        from backend.agents.cve_extractor import cve_extractor_agent
        result = cve_extractor_agent(sample_state)

        assert result["extracted_info"]["cisa_kev"] is True


class TestAttackClassifierAgent:
    """Tests for the ATT&CK classifier agent with mocked dependencies."""

    @patch("backend.agents.attack_classifier.hybrid_search")
    @patch("backend.agents.attack_classifier.get_llm")
    def test_agent_returns_techniques(self, mock_get_llm, mock_rag, sample_state, sample_extracted_info):
        mock_llm = MagicMock()
        response = MagicMock()
        response.content = json.dumps({
            "techniques": [
                {"technique_id": "T1190", "name": "Exploit", "tactics": ["initial-access"], "confidence": 0.95}
            ]
        })
        mock_llm.invoke.return_value = response
        mock_get_llm.return_value = mock_llm

        mock_rag.return_value = [
            {"technique_id": "T1190", "name": "Exploit", "tactics": ["initial-access"], "text": "description"}
        ]

        sample_state["extracted_info"] = sample_extracted_info
        from backend.agents.attack_classifier import attack_classifier_agent
        result = attack_classifier_agent(sample_state)

        assert len(result["attack_techniques"]) == 1
        assert result["attack_techniques"][0]["technique_id"] == "T1190"

    @patch("backend.agents.attack_classifier.hybrid_search")
    @patch("backend.agents.attack_classifier.get_llm")
    def test_agent_handles_rag_failure(self, mock_get_llm, mock_rag, sample_state):
        mock_rag.side_effect = Exception("Qdrant connection refused")

        from backend.agents.attack_classifier import attack_classifier_agent
        result = attack_classifier_agent(sample_state)

        assert result["attack_techniques"] == []
        assert "Qdrant unavailable" in result["messages"][0]


class TestPlaybookGeneratorAgent:
    """Tests for the playbook generator agent with mocked LLM."""

    @patch("backend.agents.playbook_generator.get_llm")
    def test_agent_generates_playbook_and_sigma(self, mock_get_llm, sample_state, sample_extracted_info):
        mock_llm = MagicMock()
        playbook_resp = MagicMock()
        playbook_resp.content = "# Incident Response Playbook: CVE-2021-44228\n## 1. Overview"
        sigma_resp = MagicMock()
        sigma_resp.content = "title: Detect Log4Shell\nstatus: experimental"
        mock_llm.invoke.side_effect = [playbook_resp, sigma_resp]
        mock_get_llm.return_value = mock_llm

        sample_state["extracted_info"] = sample_extracted_info
        sample_state["attack_techniques"] = [
            {"technique_id": "T1190", "name": "Exploit", "tactics": ["initial-access"], "confidence": 0.95}
        ]

        from backend.agents.playbook_generator import playbook_generator_agent
        result = playbook_generator_agent(sample_state)

        assert "Incident Response Playbook" in result["response_playbook"]
        assert "Detect Log4Shell" in result["sigma_rule"]
        assert "playbook" in result["messages"][0]
        assert "Sigma rule" in result["messages"][0]

    @patch("backend.agents.playbook_generator.get_llm")
    def test_agent_handles_llm_error(self, mock_get_llm, sample_state):
        mock_llm = MagicMock()
        mock_llm.invoke.side_effect = Exception("LLM timeout")
        mock_get_llm.return_value = mock_llm

        from backend.agents.playbook_generator import playbook_generator_agent
        result = playbook_generator_agent(sample_state)

        assert "Failed" in result["response_playbook"]
        assert "failed" in result["sigma_rule"]
