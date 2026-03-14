"""In-memory TTL cache for external API responses."""

from cachetools import TTLCache

from backend.config import get_settings

_settings = get_settings()

cve_cache: TTLCache = TTLCache(maxsize=256, ttl=_settings.cache_ttl_cve)
feed_cache: TTLCache = TTLCache(maxsize=256, ttl=_settings.cache_ttl_feed)
