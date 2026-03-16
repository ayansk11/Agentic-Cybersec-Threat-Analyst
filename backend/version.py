"""Read version from the VERSION file at project root."""

from pathlib import Path

VERSION_FILE = Path(__file__).resolve().parent.parent / "VERSION"


def get_version() -> str:
    """Return the current version string from the VERSION file."""
    return VERSION_FILE.read_text().strip()


__version__ = get_version()
