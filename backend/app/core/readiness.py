from dataclasses import dataclass

from redis import Redis
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import Settings


@dataclass(frozen=True, slots=True)
class ReadinessResult:
    database: bool
    redis: bool

    @property
    def ready(self) -> bool:
        return self.database and self.redis


def check_readiness(session: Session, settings: Settings) -> ReadinessResult:
    database_ready = False
    redis_ready = False
    try:
        session.execute(text("SELECT 1"))
        database_ready = True
    except Exception:
        pass

    client = Redis.from_url(
        settings.redis_url,
        socket_connect_timeout=settings.dependency_timeout_seconds,
        socket_timeout=settings.dependency_timeout_seconds,
    )
    try:
        redis_ready = bool(client.ping())
    except Exception:
        pass
    finally:
        client.close()
    return ReadinessResult(database=database_ready, redis=redis_ready)
