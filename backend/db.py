"""SQLite persistence layer for analysis results."""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

from backend.config import get_settings

logger = logging.getLogger("backend.db")

DB_PATH = Path("data/analyses.db")


async def init_db() -> None:
    """Create tables if they do not exist and run migrations."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        # ── Analyses table ──────────────────────────────────────────
        await db.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                cve_description TEXT DEFAULT '',
                extracted_info TEXT DEFAULT '{}',
                attack_techniques TEXT DEFAULT '[]',
                response_playbook TEXT DEFAULT '',
                sigma_rule TEXT DEFAULT '',
                severity TEXT DEFAULT 'UNKNOWN',
                created_at TEXT NOT NULL,
                user_id INTEGER DEFAULT NULL
            )
        """)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_analyses_cve_id ON analyses(cve_id)")
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses(created_at)"
        )

        # ── Users table ─────────────────────────────────────────────
        await db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL,
                hashed_password TEXT DEFAULT NULL,
                role TEXT NOT NULL DEFAULT 'analyst',
                oauth_provider TEXT DEFAULT NULL,
                oauth_id TEXT DEFAULT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        await db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)")

        # ── Refresh tokens table ────────────────────────────────────
        await db.execute("""
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            )
        """)
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id)"
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash)"
        )

        # ── Password reset tokens table ─────────────────────────────
        await db.execute("""
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            )
        """)
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_pw_reset_hash ON password_reset_tokens(token_hash)"
        )

        # ── Email verification tokens table ──────────────────────────
        await db.execute("""
            CREATE TABLE IF NOT EXISTS email_verification_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            )
        """)
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_email_verify_hash ON email_verification_tokens(token_hash)"
        )

        # ── App settings table (key-value) ───────────────────────────
        await db.execute("""
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        # ── Migration: add user_id to existing analyses table ───────
        try:
            await db.execute("ALTER TABLE analyses ADD COLUMN user_id INTEGER DEFAULT NULL")
            logger.info("Migrated analyses table: added user_id column")
        except Exception:
            pass  # Column already exists

        await db.execute("CREATE INDEX IF NOT EXISTS idx_analyses_user_id ON analyses(user_id)")

        # ── Migration: add email_verified to users table ────────────
        try:
            await db.execute(
                "ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0"
            )
            logger.info("Migrated users table: added email_verified column")
        except Exception:
            pass  # Column already exists

        await db.commit()

    # ── Seed admin user if configured ───────────────────────────────
    settings = get_settings()
    if settings.admin_email and settings.admin_password:
        from backend.db_users import create_user, get_user_by_email

        existing = await get_user_by_email(settings.admin_email)
        if not existing:
            from backend.api.auth import hash_password

            await create_user(
                email=settings.admin_email,
                username="Admin",
                hashed_password=hash_password(settings.admin_password),
                role="admin",
            )
            logger.info("Seeded admin user: %s", settings.admin_email)


async def save_analysis(
    cve_id: str,
    cve_description: str,
    extracted_info: dict,
    attack_techniques: list[dict],
    response_playbook: str,
    sigma_rule: str,
    user_id: int | None = None,
) -> int:
    """Save a completed analysis and return its ID."""
    severity = extracted_info.get(
        "nvd_severity", extracted_info.get("severity_assessment", "UNKNOWN")
    )
    if severity and " " in severity:
        severity = severity.split()[0]

    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """INSERT INTO analyses
               (cve_id, cve_description, extracted_info, attack_techniques,
                response_playbook, sigma_rule, severity, created_at, user_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                cve_id,
                cve_description,
                json.dumps(extracted_info, default=str),
                json.dumps(attack_techniques, default=str),
                response_playbook,
                sigma_rule,
                severity or "UNKNOWN",
                datetime.now(timezone.utc).isoformat(),
                user_id,
            ),
        )
        await db.commit()
        return cursor.lastrowid


async def get_analysis(analysis_id: int, user_id: int | None = None) -> dict | None:
    """Fetch a single analysis by ID. Optionally filter by user ownership."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        if user_id is not None:
            cursor = await db.execute(
                "SELECT * FROM analyses WHERE id = ? AND user_id = ?",
                (analysis_id, user_id),
            )
        else:
            cursor = await db.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,))
        row = await cursor.fetchone()
        if not row:
            return None
        return _row_to_dict(row)


async def get_analysis_history(
    limit: int = 50, offset: int = 0, user_id: int | None = None
) -> list[dict]:
    """Fetch analysis history, most recent first. Optionally filter by user."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        if user_id is not None:
            cursor = await db.execute(
                "SELECT * FROM analyses WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (user_id, limit, offset),
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM analyses ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            )
        rows = await cursor.fetchall()
        return [_row_to_dict(r) for r in rows]


async def get_severity_counts(user_id: int | None = None) -> dict[str, int]:
    """Get count of analyses grouped by severity."""
    async with aiosqlite.connect(DB_PATH) as db:
        if user_id is not None:
            cursor = await db.execute(
                "SELECT severity, COUNT(*) as cnt FROM analyses WHERE user_id = ? GROUP BY severity",
                (user_id,),
            )
        else:
            cursor = await db.execute(
                "SELECT severity, COUNT(*) as cnt FROM analyses GROUP BY severity"
            )
        rows = await cursor.fetchall()
        return {row[0]: row[1] for row in rows}


async def get_tactic_counts(user_id: int | None = None) -> dict[str, int]:
    """Get count of technique-tactic pairs across analyses."""
    async with aiosqlite.connect(DB_PATH) as db:
        if user_id is not None:
            cursor = await db.execute(
                "SELECT attack_techniques FROM analyses WHERE user_id = ?", (user_id,)
            )
        else:
            cursor = await db.execute("SELECT attack_techniques FROM analyses")
        rows = await cursor.fetchall()

    tactic_counts: dict[str, int] = {}
    for (techniques_json,) in rows:
        try:
            techniques = json.loads(techniques_json)
            for t in techniques:
                for tactic in t.get("tactics", []):
                    tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        except (json.JSONDecodeError, TypeError):
            pass
    return tactic_counts


def _row_to_dict(row) -> dict:
    d = dict(row)
    d["extracted_info"] = json.loads(d.get("extracted_info", "{}"))
    d["attack_techniques"] = json.loads(d.get("attack_techniques", "[]"))
    return d
