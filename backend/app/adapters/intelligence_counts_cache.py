"""Best-effort persistence of public aggregate counts across API restarts."""

import json
from functools import lru_cache

from redis import Redis
from redis.exceptions import RedisError

from app.core.config import get_settings

KEY = "intelligence:public-counts:v1"


@lru_cache
def _client() -> Redis:
    return Redis.from_url(get_settings().redis_url, socket_timeout=0.5,
                          socket_connect_timeout=0.5, decode_responses=True)


def read_counts() -> dict:
    try:
        counts = json.loads(_client().get(KEY) or "{}")
        if isinstance(counts, dict) and all(
            type(counts.get(key)) is int and counts[key] >= 0
            for key in ("cves", "products", "product_families")
        ):
            return counts
    except (RedisError, ValueError, TypeError):
        pass
    return {}


def write_counts(counts: dict) -> None:
    try:
        _client().set(KEY, json.dumps(counts))
    except RedisError:
        pass  # Cache loss must never stop ingestion or the dashboard.
