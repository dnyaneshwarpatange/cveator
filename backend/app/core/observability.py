import contextvars
import json
import logging
import re
import time
from datetime import UTC, datetime
from uuid import uuid4

from fastapi import Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

from app.core.config import Settings

request_id_context: contextvars.ContextVar[str] = contextvars.ContextVar(
    "request_id", default="system"
)
_safe_request_id = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
_request_count = Counter(
    "cve_monitor_http_requests_total",
    "HTTP requests handled by the API",
    ("method", "route", "status"),
)
_request_duration = Histogram(
    "cve_monitor_http_request_duration_seconds",
    "HTTP request latency",
    ("method", "route"),
)


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": request_id_context.get(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(settings: Settings) -> None:
    root = logging.getLogger()
    root.setLevel(settings.log_level.upper())
    if settings.log_format != "json":
        return
    handler = logging.StreamHandler()
    handler.setFormatter(JsonLogFormatter())
    root.handlers.clear()
    root.addHandler(handler)


async def observe_request(request: Request, call_next) -> Response:
    supplied_request_id = request.headers.get("x-request-id", "")
    request_id = (
        supplied_request_id if _safe_request_id.fullmatch(supplied_request_id) else uuid4().hex
    )
    token = request_id_context.set(request_id)
    started = time.perf_counter()
    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response
    finally:
        route = request.scope.get("route")
        route_path = getattr(route, "path", "unmatched")
        method = request.method
        _request_count.labels(method=method, route=route_path, status=str(status_code)).inc()
        _request_duration.labels(method=method, route=route_path).observe(
            time.perf_counter() - started
        )
        request_id_context.reset(token)


def metrics_response() -> Response:
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
