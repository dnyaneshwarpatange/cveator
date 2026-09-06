from datetime import datetime
from typing import Protocol

from app.domain.cve import FetchResult


class CveFeed(Protocol):
    source_name: str

    def fetch_since(self, since: datetime) -> FetchResult: ...
