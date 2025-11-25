"""Shared Redis client factory for the token blocklist."""

import redis
from django.conf import settings

_client: redis.Redis | None = None


def get_redis_client() -> redis.Redis:
    """Return a singleton Redis client using REDIS_URL from settings."""

    global _client
    if _client is None:
        _client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
    return _client


__all__ = ["get_redis_client"]
