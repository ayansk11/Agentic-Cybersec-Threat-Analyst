"""Tests for SQLite persistence layer."""

from unittest.mock import patch

import pytest

from backend import db


@pytest.fixture
def tmp_db(tmp_path):
    """Use a temporary database for each test."""
    test_db = tmp_path / "test_analyses.db"
    with patch.object(db, "DB_PATH", test_db):
        yield test_db


class TestInitDB:
    async def test_creates_database(self, tmp_db):
        await db.init_db()
        assert tmp_db.exists()

    async def test_idempotent(self, tmp_db):
        await db.init_db()
        await db.init_db()  # Should not raise
        assert tmp_db.exists()


class TestSaveAnalysis:
    async def test_returns_integer_id(self, tmp_db):
        await db.init_db()
        aid = await db.save_analysis(
            cve_id="CVE-2021-44228",
            cve_description="Log4j RCE",
            extracted_info={"severity_assessment": "CRITICAL"},
            attack_techniques=[{"technique_id": "T1190", "name": "Exploit App", "tactics": ["initial-access"], "confidence": 0.95}],
            response_playbook="# Playbook",
            sigma_rule="title: test",
        )
        assert isinstance(aid, int)
        assert aid > 0

    async def test_severity_extracted(self, tmp_db):
        await db.init_db()
        aid = await db.save_analysis(
            cve_id="CVE-2021-44228",
            cve_description="",
            extracted_info={"nvd_severity": "CRITICAL"},
            attack_techniques=[],
            response_playbook="",
            sigma_rule="",
        )
        result = await db.get_analysis(aid)
        assert result["severity"] == "CRITICAL"


class TestGetAnalysis:
    async def test_returns_none_for_missing(self, tmp_db):
        await db.init_db()
        result = await db.get_analysis(9999)
        assert result is None

    async def test_returns_saved_record(self, tmp_db):
        await db.init_db()
        aid = await db.save_analysis(
            cve_id="CVE-2024-0001",
            cve_description="Test vuln",
            extracted_info={"summary": "Test"},
            attack_techniques=[],
            response_playbook="playbook text",
            sigma_rule="sigma yaml",
        )
        result = await db.get_analysis(aid)
        assert result is not None
        assert result["cve_id"] == "CVE-2024-0001"
        assert result["extracted_info"]["summary"] == "Test"
        assert result["response_playbook"] == "playbook text"


class TestGetAnalysisHistory:
    async def test_returns_descending_order(self, tmp_db):
        await db.init_db()
        await db.save_analysis("CVE-0001", "", {}, [], "", "")
        await db.save_analysis("CVE-0002", "", {}, [], "", "")
        history = await db.get_analysis_history()
        assert len(history) == 2
        assert history[0]["cve_id"] == "CVE-0002"  # Most recent first

    async def test_respects_limit(self, tmp_db):
        await db.init_db()
        for i in range(5):
            await db.save_analysis(f"CVE-{i}", "", {}, [], "", "")
        history = await db.get_analysis_history(limit=3)
        assert len(history) == 3


class TestSeverityCounts:
    async def test_groups_by_severity(self, tmp_db):
        await db.init_db()
        await db.save_analysis("CVE-1", "", {"nvd_severity": "CRITICAL"}, [], "", "")
        await db.save_analysis("CVE-2", "", {"nvd_severity": "CRITICAL"}, [], "", "")
        await db.save_analysis("CVE-3", "", {"nvd_severity": "HIGH"}, [], "", "")
        counts = await db.get_severity_counts()
        assert counts["CRITICAL"] == 2
        assert counts["HIGH"] == 1


class TestTacticCounts:
    async def test_counts_tactics(self, tmp_db):
        await db.init_db()
        techniques = [
            {"technique_id": "T1190", "tactics": ["initial-access"], "confidence": 0.9},
            {"technique_id": "T1059", "tactics": ["execution", "initial-access"], "confidence": 0.8},
        ]
        await db.save_analysis("CVE-1", "", {}, techniques, "", "")
        counts = await db.get_tactic_counts()
        assert counts["initial-access"] == 2
        assert counts["execution"] == 1
