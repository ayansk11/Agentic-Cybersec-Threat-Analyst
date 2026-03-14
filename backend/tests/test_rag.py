"""Tests for the RAG pipeline (chunker and retriever)."""

from backend.rag.chunker import (
    chunk_techniques,
    chunk_mitigations,
    chunk_software,
    chunk_groups,
    chunk_relationships,
)


# ── Chunker tests ─────────────────────────────────────────────────────


class TestChunkTechniques:
    """Tests for technique chunking."""

    def test_basic_technique(self):
        techniques = [
            {
                "text": "Exploit Public-Facing Application description",
                "technique_id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactics": ["initial-access"],
                "platforms": ["Linux", "Windows"],
                "detection": "Short detection info",
            }
        ]
        chunks = chunk_techniques(techniques)
        assert len(chunks) == 1
        assert chunks[0]["technique_id"] == "T1190"
        assert chunks[0]["chunk_type"] == "technique"

    def test_technique_with_long_detection(self):
        """Long detection info produces an extra detection chunk."""
        techniques = [
            {
                "text": "T1059 description",
                "technique_id": "T1059",
                "name": "Command and Scripting Interpreter",
                "tactics": ["execution"],
                "platforms": ["Linux"],
                "detection": "x" * 300,
            }
        ]
        chunks = chunk_techniques(techniques)
        assert len(chunks) == 2
        assert chunks[0]["chunk_type"] == "technique"
        assert chunks[1]["chunk_type"] == "detection"

    def test_empty_list(self):
        assert chunk_techniques([]) == []


class TestChunkMitigations:
    """Tests for mitigation chunking."""

    def test_basic_mitigation(self):
        mitigations = [
            {
                "mitigation_id": "M1050",
                "name": "Exploit Protection",
                "description": "Use exploit protection features.",
            }
        ]
        chunks = chunk_mitigations(mitigations)
        assert len(chunks) == 1
        assert chunks[0]["entity_id"] == "M1050"
        assert chunks[0]["chunk_type"] == "mitigation"
        assert "Exploit Protection" in chunks[0]["text"]

    def test_empty_list(self):
        assert chunk_mitigations([]) == []


class TestChunkSoftware:
    """Tests for software chunking."""

    def test_basic_software(self):
        software = [
            {
                "software_id": "S0154",
                "name": "Cobalt Strike",
                "software_type": "tool",
                "description": "Commercial adversary simulation tool.",
                "aliases": ["CobaltStrike"],
                "platforms": ["Windows"],
            }
        ]
        chunks = chunk_software(software)
        assert len(chunks) == 1
        assert chunks[0]["chunk_type"] == "software"
        assert "Cobalt Strike" in chunks[0]["text"]
        assert "CobaltStrike" in chunks[0]["text"]

    def test_software_no_aliases(self):
        software = [
            {
                "software_id": "S0001",
                "name": "TestTool",
                "software_type": "malware",
                "description": "A test tool.",
            }
        ]
        chunks = chunk_software(software)
        assert len(chunks) == 1
        assert "Aliases" not in chunks[0]["text"]

    def test_empty_list(self):
        assert chunk_software([]) == []


class TestChunkGroups:
    """Tests for group chunking."""

    def test_basic_group(self):
        groups = [
            {
                "group_id": "G0016",
                "name": "APT29",
                "description": "Russian threat group.",
                "aliases": ["Cozy Bear", "NOBELIUM"],
            }
        ]
        chunks = chunk_groups(groups)
        assert len(chunks) == 1
        assert chunks[0]["chunk_type"] == "group"
        assert "APT29" in chunks[0]["text"]
        assert "Cozy Bear" in chunks[0]["text"]

    def test_empty_list(self):
        assert chunk_groups([]) == []


class TestChunkRelationships:
    """Tests for relationship chunking."""

    def test_mitigates_relationship(self):
        relationships = [
            {
                "source_ref": "mitigation-1",
                "target_ref": "attack-pattern-1",
                "relationship_type": "mitigates",
                "description": "M1050 mitigates T1190.",
            }
        ]
        id_lookup = {
            "mitigation-1": {
                "external_id": "M1050",
                "name": "Exploit Protection",
                "entity_type": "mitigation",
            },
            "attack-pattern-1": {
                "external_id": "T1190",
                "name": "Exploit Public-Facing App",
                "entity_type": "technique",
            },
        }
        chunks = chunk_relationships(relationships, id_lookup)
        assert len(chunks) == 1
        assert chunks[0]["chunk_type"] == "relationship"
        assert "mitigates" in chunks[0]["text"]
        assert "M1050" in chunks[0]["text"]

    def test_uses_relationship_group(self):
        relationships = [
            {
                "source_ref": "group-1",
                "target_ref": "attack-pattern-1",
                "relationship_type": "uses",
                "description": "APT29 uses T1059.",
            }
        ]
        id_lookup = {
            "group-1": {"external_id": "G0016", "name": "APT29", "entity_type": "group"},
            "attack-pattern-1": {
                "external_id": "T1059",
                "name": "Command Interpreter",
                "entity_type": "technique",
            },
        }
        chunks = chunk_relationships(relationships, id_lookup)
        assert "Group G0016" in chunks[0]["text"]

    def test_uses_relationship_software(self):
        relationships = [
            {
                "source_ref": "software-1",
                "target_ref": "attack-pattern-1",
                "relationship_type": "uses",
                "description": "Cobalt Strike uses T1059.",
            }
        ]
        id_lookup = {
            "software-1": {
                "external_id": "S0154",
                "name": "Cobalt Strike",
                "entity_type": "software",
            },
            "attack-pattern-1": {
                "external_id": "T1059",
                "name": "Command Interpreter",
                "entity_type": "technique",
            },
        }
        chunks = chunk_relationships(relationships, id_lookup)
        assert "Software S0154" in chunks[0]["text"]

    def test_unknown_refs(self):
        relationships = [
            {
                "source_ref": "missing-1",
                "target_ref": "missing-2",
                "relationship_type": "related-to",
                "description": "Unknown relationship.",
            }
        ]
        chunks = chunk_relationships(relationships, {})
        assert len(chunks) == 1
        assert "Unknown" in chunks[0]["text"]

    def test_empty_list(self):
        assert chunk_relationships([], {}) == []
