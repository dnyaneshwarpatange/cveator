from typing import Protocol


class RateLimiter(Protocol):
    def allow(self, *, key: str, limit: int, window_seconds: int) -> bool: ...
