#!/usr/bin/env python3
"""Bump semantic version across all project files."""

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION_FILE = ROOT / "VERSION"
PYPROJECT = ROOT / "backend" / "pyproject.toml"
PACKAGE_JSON = ROOT / "frontend" / "package.json"


def bump(current: str, part: str) -> str:
    """Bump version string by the given part (major, minor, patch)."""
    major, minor, patch = (int(x) for x in current.split("."))
    if part == "major":
        return f"{major + 1}.0.0"
    elif part == "minor":
        return f"{major}.{minor + 1}.0"
    elif part == "patch":
        return f"{major}.{minor}.{patch + 1}"
    else:
        print(f"Unknown bump type: {part}")
        print("Usage: python scripts/bump_version.py [patch|minor|major]")
        sys.exit(1)


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python scripts/bump_version.py [patch|minor|major]")
        sys.exit(1)

    part = sys.argv[1]
    current = VERSION_FILE.read_text().strip()
    new = bump(current, part)

    # 1. Update VERSION file
    VERSION_FILE.write_text(new + "\n")
    print(f"  VERSION: {current} → {new}")

    # 2. Update pyproject.toml
    toml_text = PYPROJECT.read_text()
    toml_text = re.sub(
        r'version\s*=\s*"[^"]*"', f'version = "{new}"', toml_text, count=1
    )
    PYPROJECT.write_text(toml_text)
    print(f"  backend/pyproject.toml: updated")

    # 3. Update package.json
    pkg = json.loads(PACKAGE_JSON.read_text())
    pkg["version"] = new
    PACKAGE_JSON.write_text(json.dumps(pkg, indent=2) + "\n")
    print(f"  frontend/package.json: updated")

    # 4. Git commit + tag
    subprocess.run(
        ["git", "add", str(VERSION_FILE), str(PYPROJECT), str(PACKAGE_JSON)],
        check=True,
    )
    subprocess.run(
        ["git", "commit", "-m", f"release: v{new}"],
        check=True,
    )
    subprocess.run(["git", "tag", f"v{new}"], check=True)

    print(f"\n  ✅ {current} → {new}")
    print(f"  Tagged: v{new}")
    print(f"  Run: git push && git push --tags\n")


if __name__ == "__main__":
    main()
