"""SQLite persistence layer for user accounts and refresh tokens."""

from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

DB_PATH = Path("data/analyses.db")


async def create_user(
    email: str,
    username: str,
    hashed_password: str | None = None,
    role: str = "analyst",
    oauth_provider: str | None = None,
    oauth_id: str | None = None,
) -> int:
    """Create a new user and return their ID."""
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """INSERT INTO users
               (email, username, hashed_password, role, oauth_provider, oauth_id,
                is_active, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)""",
            (email, username, hashed_password, role, oauth_provider, oauth_id, now, now),
        )
        await db.commit()
        return cursor.lastrowid


async def get_user_by_email(email: str) -> dict | None:
    """Fetch a user by email address."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM users WHERE email = ?", (email,))
        row = await cursor.fetchone()
        return dict(row) if row else None


async def get_user_by_id(user_id: int) -> dict | None:
    """Fetch a user by ID."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None


async def get_user_by_oauth(provider: str, oauth_id: str) -> dict | None:
    """Fetch a user by OAuth provider and provider-specific ID."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM users WHERE oauth_provider = ? AND oauth_id = ?",
            (provider, oauth_id),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def update_user(user_id: int, **fields) -> None:
    """Update user fields by ID."""
    if not fields:
        return
    fields["updated_at"] = datetime.now(timezone.utc).isoformat()
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [user_id]
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(f"UPDATE users SET {set_clause} WHERE id = ?", values)
        await db.commit()


async def list_users(limit: int = 50, offset: int = 0) -> list[dict]:
    """List all users, most recent first."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def count_users() -> int:
    """Return total number of users."""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT COUNT(*) FROM users")
        row = await cursor.fetchone()
        return row[0]


async def deactivate_user(user_id: int) -> None:
    """Deactivate a user (set is_active = 0)."""
    await update_user(user_id, is_active=0)


# ── Refresh Tokens ──────────────────────────────────────────────────────


async def store_refresh_token(user_id: int, token_hash: str, expires_at: str) -> None:
    """Store a hashed refresh token."""
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO refresh_tokens
               (user_id, token_hash, expires_at, created_at, revoked)
               VALUES (?, ?, ?, ?, 0)""",
            (user_id, token_hash, expires_at, now),
        )
        await db.commit()


async def verify_refresh_token(token_hash: str) -> dict | None:
    """Look up a refresh token by hash. Returns the row if valid (not expired, not revoked)."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """SELECT * FROM refresh_tokens
               WHERE token_hash = ? AND revoked = 0 AND expires_at > ?""",
            (token_hash, datetime.now(timezone.utc).isoformat()),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def revoke_refresh_token(token_hash: str) -> None:
    """Revoke a specific refresh token."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?",
            (token_hash,),
        )
        await db.commit()


async def revoke_all_user_tokens(user_id: int) -> None:
    """Revoke all refresh tokens for a user."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?",
            (user_id,),
        )
        await db.commit()


# ── Password Reset Tokens ─────────────────────────────────────────────


async def store_password_reset_token(user_id: int, token_hash: str, expires_at: str) -> None:
    """Store a hashed password reset token."""
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO password_reset_tokens
               (user_id, token_hash, expires_at, created_at, used)
               VALUES (?, ?, ?, ?, 0)""",
            (user_id, token_hash, expires_at, now),
        )
        await db.commit()


async def verify_password_reset_token(token_hash: str) -> dict | None:
    """Look up a reset token by hash. Returns the row if valid."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """SELECT * FROM password_reset_tokens
               WHERE token_hash = ? AND used = 0 AND expires_at > ?""",
            (token_hash, datetime.now(timezone.utc).isoformat()),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def consume_password_reset_token(token_hash: str) -> None:
    """Mark a reset token as used."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE password_reset_tokens SET used = 1 WHERE token_hash = ?",
            (token_hash,),
        )
        await db.commit()


# ── Email Verification Tokens ─────────────────────────────────────────


async def store_verification_token(user_id: int, token_hash: str, expires_at: str) -> None:
    """Store a hashed email verification token."""
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO email_verification_tokens
               (user_id, token_hash, expires_at, created_at, used)
               VALUES (?, ?, ?, ?, 0)""",
            (user_id, token_hash, expires_at, now),
        )
        await db.commit()


async def verify_email_token(token_hash: str) -> dict | None:
    """Look up a verification token by hash. Returns the row if valid."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """SELECT * FROM email_verification_tokens
               WHERE token_hash = ? AND used = 0 AND expires_at > ?""",
            (token_hash, datetime.now(timezone.utc).isoformat()),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def consume_verification_token(token_hash: str) -> None:
    """Mark a verification token as used."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE email_verification_tokens SET used = 1 WHERE token_hash = ?",
            (token_hash,),
        )
        await db.commit()


# ── App Settings (key-value store) ───────────────────────────────────


async def get_app_setting(key: str) -> str | None:
    """Get a setting value by key."""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT value FROM app_settings WHERE key = ?", (key,))
        row = await cursor.fetchone()
        return row[0] if row else None


async def set_app_setting(key: str, value: str) -> None:
    """Set a setting value (upsert)."""
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO app_settings (key, value, updated_at)
               VALUES (?, ?, ?)
               ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = ?""",
            (key, value, now, value, now),
        )
        await db.commit()


async def get_app_settings_bulk(keys: list[str]) -> dict[str, str]:
    """Get multiple settings at once."""
    if not keys:
        return {}
    placeholders = ",".join("?" for _ in keys)
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            f"SELECT key, value FROM app_settings WHERE key IN ({placeholders})",
            keys,
        )
        rows = await cursor.fetchall()
        return {row[0]: row[1] for row in rows}
