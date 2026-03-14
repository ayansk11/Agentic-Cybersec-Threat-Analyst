"""Entity-level chunking for MITRE ATT&CK data (techniques, mitigations, software, groups, relationships)."""


def chunk_techniques(techniques: list[dict]) -> list[dict]:
    """Convert extracted techniques into chunks ready for embedding.

    Uses entity-level chunking: each technique becomes one chunk containing
    its ID, name, description, tactics, platforms, and detection info.
    """
    chunks = []
    for tech in techniques:
        chunks.append(
            {
                "text": tech["text"],
                "technique_id": tech["technique_id"],
                "name": tech["name"],
                "tactics": tech.get("tactics", []),
                "platforms": tech.get("platforms", []),
                "chunk_type": "technique",
            }
        )

        # If detection info is substantial, create a separate detection chunk
        detection = tech.get("detection", "")
        if len(detection) > 200:
            chunks.append(
                {
                    "text": (
                        f"Detection for ATT&CK {tech['technique_id']} - {tech['name']}:\n"
                        f"{detection}"
                    ),
                    "technique_id": tech["technique_id"],
                    "name": tech["name"],
                    "tactics": tech.get("tactics", []),
                    "platforms": tech.get("platforms", []),
                    "chunk_type": "detection",
                }
            )

    return chunks


def chunk_mitigations(mitigations: list[dict]) -> list[dict]:
    """Convert extracted mitigations into chunks ready for embedding."""
    chunks = []
    for mit in mitigations:
        text = f"ATT&CK Mitigation {mit['mitigation_id']} - {mit['name']}\n{mit['description']}"
        chunks.append(
            {
                "text": text,
                "entity_id": mit["mitigation_id"],
                "name": mit["name"],
                "chunk_type": "mitigation",
            }
        )
    return chunks


def chunk_software(software_list: list[dict]) -> list[dict]:
    """Convert extracted software entries into chunks ready for embedding."""
    chunks = []
    for sw in software_list:
        aliases = ", ".join(sw.get("aliases", [])) if sw.get("aliases") else ""
        platforms = ", ".join(sw.get("platforms", [])) if sw.get("platforms") else ""

        parts = [f"ATT&CK Software {sw['software_id']} - {sw['name']} ({sw['software_type']})"]
        if aliases:
            parts.append(f"Aliases: {aliases}")
        if platforms:
            parts.append(f"Platforms: {platforms}")
        parts.append(sw["description"])

        chunks.append(
            {
                "text": "\n".join(parts),
                "entity_id": sw["software_id"],
                "name": sw["name"],
                "software_type": sw["software_type"],
                "chunk_type": "software",
            }
        )
    return chunks


def chunk_groups(groups: list[dict]) -> list[dict]:
    """Convert extracted groups into chunks ready for embedding."""
    chunks = []
    for grp in groups:
        aliases = ", ".join(grp.get("aliases", [])) if grp.get("aliases") else ""

        parts = [f"ATT&CK Group {grp['group_id']} - {grp['name']}"]
        if aliases:
            parts.append(f"Aliases: {aliases}")
        parts.append(grp["description"])

        chunks.append(
            {
                "text": "\n".join(parts),
                "entity_id": grp["group_id"],
                "name": grp["name"],
                "chunk_type": "group",
            }
        )
    return chunks


def chunk_relationships(relationships: list[dict], id_lookup: dict) -> list[dict]:
    """Convert extracted relationships into chunks ready for embedding.

    Uses id_lookup to resolve STIX IDs to human-readable names.
    """
    chunks = []
    for rel in relationships:
        source = id_lookup.get(rel["source_ref"], {})
        target = id_lookup.get(rel["target_ref"], {})

        source_id = source.get("external_id", "?")
        source_name = source.get("name", "Unknown")
        source_type = source.get("entity_type", "unknown")
        target_id = target.get("external_id", "?")
        target_name = target.get("name", "Unknown")

        rel_type = rel["relationship_type"]
        desc = rel["description"]

        if rel_type == "mitigates":
            header = f"Mitigation {source_id} ({source_name}) mitigates Technique {target_id} ({target_name})"
        elif rel_type == "subtechnique-of":
            header = f"Technique {source_id} ({source_name}) is a sub-technique of {target_id} ({target_name})"
        elif rel_type == "uses" and source_type == "group":
            header = f"Group {source_id} ({source_name}) uses Technique {target_id} ({target_name})"
        elif rel_type == "uses" and source_type == "software":
            header = (
                f"Software {source_id} ({source_name}) uses Technique {target_id} ({target_name})"
            )
        else:
            header = f"{source_id} ({source_name}) {rel_type} {target_id} ({target_name})"

        chunks.append(
            {
                "text": f"{header}\n{desc}",
                "source_id": source_id,
                "target_id": target_id,
                "relationship_type": rel_type,
                "chunk_type": "relationship",
            }
        )
    return chunks
