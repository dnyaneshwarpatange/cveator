from redis import Redis


class RedisRateLimiter:
    _increment_script = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return current
"""

    def __init__(self, redis_url: str, *, timeout_seconds: float) -> None:
        self._client = Redis.from_url(
            redis_url,
            socket_connect_timeout=timeout_seconds,
            socket_timeout=timeout_seconds,
        )

    def allow(self, *, key: str, limit: int, window_seconds: int) -> bool:
        current = int(self._client.eval(self._increment_script, 1, key, window_seconds))
        return current <= limit
