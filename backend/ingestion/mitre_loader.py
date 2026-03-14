"""MITRE ATT&CK STIX data loader and parser."""

import json
from pathlib import Path

import httpx

from backend.config import get_settings


def download_attack_data(path: str | None = None) -> str:
    """Download the MITRE ATT&CK Enterprise STIX bundle."""
    settings = get_settings()
    path = path or settings.attack_data_path
    filepath = Path(path)
    filepath.parent.mkdir(parents=True, exist_ok=True)

    print(f"Downloading ATT&CK STIX data to {path}...")
    resp = httpx.get(settings.attack_stix_url, timeout=60.0)
    resp.raise_for_status()

    filepath.write_text(resp.text)
    print(f"Downloaded ({filepath.stat().st_size / 1024 / 1024:.1f} MB)")
    return path


def extract_techniques(path: str | None = None) -> list[dict]:
    """Parse ATT&CK STIX JSON and extract technique records.

    Returns a list of dicts with: technique_id, name, description,
    tactics, platforms, detection, url, text (for embedding).
    """
    settings = get_settings()
    path = path or settings.attack_data_path
    filepath = Path(path)

    if not filepath.exists():
        download_attack_data(path)

    data = json.loads(filepath.read_text())
    objects = data.get("objects", [])

    techniques = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        # Extract technique ID from external references
        tech_id = None
        url = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id")
                url = ref.get("url", "")
                break

        if not tech_id:
            continue

        name = obj.get("name", "")
        description = obj.get("description", "")
        detection = obj.get("x_mitre_detection", "")
        platforms = obj.get("x_mitre_platforms", [])

        tactics = [
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        # Composite text for embedding
        text = (
            f"ATT&CK {tech_id} - {name}\n"
            f"Tactics: {', '.join(tactics)}\n"
            f"Platforms: {', '.join(platforms)}\n"
            f"{description}\n"
            f"Detection: {detection}"
        )

        techniques.append(
            {
                "technique_id": tech_id,
                "name": name,
                "description": description,
                "tactics": tactics,
                "platforms": platforms,
                "detection": detection,
                "url": url,
                "text": text,
            }
        )

    print(f"Extracted {len(techniques)} techniques from ATT&CK STIX data")
    return techniques


def extract_groups(path: str | None = None) -> list[dict]:
    """Extract threat group/actor records from ATT&CK STIX data."""
    settings = get_settings()
    path = path or settings.attack_data_path
    filepath = Path(path)

    if not filepath.exists():
        download_attack_data(path)

    data = json.loads(filepath.read_text())

    groups = []
    for obj in data.get("objects", []):
        if obj.get("type") != "intrusion-set":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        group_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                group_id = ref.get("external_id")
                break

        if not group_id:
            continue

        groups.append(
            {
                "group_id": group_id,
                "name": obj.get("name", ""),
                "description": obj.get("description", ""),
                "aliases": obj.get("aliases", []),
            }
        )

    print(f"Extracted {len(groups)} groups from ATT&CK STIX data")
    return groups


def extract_mitigations(path: str | None = None) -> list[dict]:
    """Extract mitigation (course-of-action) records from ATT&CK STIX data.

    Returns a list of dicts with: mitigation_id, name, description.
    """
    settings = get_settings()
    path = path or settings.attack_data_path
    filepath = Path(path)

    if not filepath.exists():
        download_attack_data(path)

    data = json.loads(filepath.read_text())

    mitigations = []
    for obj in data.get("objects", []):
        if obj.get("type") != "course-of-action":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        mitigation_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                mitigation_id = ref.get("external_id")
                break

        if not mitigation_id:
            continue

        mitigations.append(
            {
                "mitigation_id": mitigation_id,
                "name": obj.get("name", ""),
                "description": obj.get("description", ""),
            }
        )

    print(f"Extracted {len(mitigations)} mitigations from ATT&CK STIX data")
    return mitigations


def extract_software(path: str | None = None) -> list[dict]:
    """Extract software (malware + tool) records from ATT&CK STIX data.

    Returns a list of dicts with: software_id, name, description,
    software_type, platforms, aliases.
    """
    settings = get_settings()
    path = path or settings.attack_data_path
    filepath = Path(path)

    if not filepath.exists():
        download_attack_data(path)

    data = json.loads(filepath.read_text())

    software = []
    for obj in data.get("objects", []):
        if obj.get("type") not in ("malware", "tool"):
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        software_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                software_id = ref.get("external_id")
                break

        if not software_id:
            continue

        software.append(
            {
                "software_id": software_id,
                "name": obj.get("name", ""),
                "description": obj.get("description", ""),
                "software_type": obj.get("type", ""),
                "platforms": obj.get("x_mitre_platforms", []),
                "aliases": obj.get("x_mitre_aliases", []),
            }
        )

    print(f"Extracted {len(software)} software entries from ATT&CK STIX data")
    return software


def extract_relationships(path: str | None = None) -> tuple[list[dict], dict]:
    """Extract relationship records and a STIX ID lookup from ATT&CK STIX data.

    Only keeps: mitigates, uses, subtechnique-of relationships.
    Skips relationships with empty descriptions (no RAG value).

    Returns:
        (relationships, id_lookup) where id_lookup maps STIX ID →
        {"external_id": "T1059", "name": "Command and Scripting Interpreter", "type": "technique"}
    """
    settings = get_settings()
    path = path or settings.attack_data_path
    filepath = Path(path)

    if not filepath.exists():
        download_attack_data(path)

    data = json.loads(filepath.read_text())
    objects = data.get("objects", [])

    # Build STIX ID → (external_id, name, entity_type) lookup for all entity types
    type_map = {
        "attack-pattern": "technique",
        "course-of-action": "mitigation",
        "intrusion-set": "group",
        "malware": "software",
        "tool": "software",
    }
    id_lookup: dict[str, dict] = {}
    for obj in objects:
        obj_type = obj.get("type", "")
        if obj_type not in type_map:
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        stix_id = obj.get("id", "")
        external_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                external_id = ref.get("external_id")
                break

        if stix_id and external_id:
            id_lookup[stix_id] = {
                "external_id": external_id,
                "name": obj.get("name", ""),
                "entity_type": type_map[obj_type],
            }

    # Extract relationships
    allowed_types = {"mitigates", "uses", "subtechnique-of"}
    relationships = []
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        rel_type = obj.get("relationship_type", "")
        if rel_type not in allowed_types:
            continue

        description = obj.get("description", "")
        # Skip relationships with no description — they add no RAG context
        if not description.strip():
            continue

        source_ref = obj.get("source_ref", "")
        target_ref = obj.get("target_ref", "")

        # Both ends must be in our lookup (known, non-revoked entities)
        if source_ref not in id_lookup or target_ref not in id_lookup:
            continue

        relationships.append(
            {
                "source_ref": source_ref,
                "target_ref": target_ref,
                "relationship_type": rel_type,
                "description": description,
            }
        )

    print(f"Extracted {len(relationships)} relationships from ATT&CK STIX data")
    print(f"  ID lookup covers {len(id_lookup)} entities")
    return relationships, id_lookup


if __name__ == "__main__":
    techniques = extract_techniques()
    print("\nSample technique:")
    if techniques:
        import json as _json

        print(_json.dumps(techniques[0], indent=2, default=str)[:500])
