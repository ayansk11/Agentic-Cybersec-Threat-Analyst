"""Rate limiter singleton (separate module to avoid circular imports)."""

from starlette.requests import Request

from slowapi import Limiter


def _get_rate_limit_key(request: Request) -> str:
    """Rate limit by user ID if authenticated, otherwise by IP."""
    user_id = getattr(request.state, "user_id", None)
    if user_id:
        return f"user:{user_id}"
    return request.client.host if request.client else "unknown"


limiter = Limiter(key_func=_get_rate_limit_key)
