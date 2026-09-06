"""Verified streaming access to NVD's official CVE 2.0 yearly feeds."""

import gzip
import hashlib
import re
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import httpx
import ijson

from app.adapters.nvd import normalize_nvd_vulnerability
from app.domain.cve import NormalizedCve

NVD_FEED_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"
NVD_FIRST_FEED_YEAR = 2002  # This file also contains all CVEs from earlier years.


class InvalidNvdFeed(ValueError):
    pass


class NvdYearlyFeed:
    def __init__(self, *, client: httpx.Client | None = None) -> None:
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(180, connect=30), follow_redirects=True
        )
        self._owns_client = client is None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    @contextmanager
    def records(self, year: int) -> Iterator[Iterator[NormalizedCve]]:
        """Download once, verify the uncompressed digest, then parse in bounded memory."""
        if not NVD_FIRST_FEED_YEAR <= year <= 2100:
            raise ValueError("Unsupported NVD feed year")
        base = f"{NVD_FEED_BASE}/nvdcve-2.0-{year}"
        metadata_response = self._client.get(f"{base}.meta")
        metadata_response.raise_for_status()
        expected = _metadata_checksum(metadata_response.text)
        with tempfile.TemporaryDirectory(prefix="cve-nvd-") as directory:
            compressed = Path(directory) / "feed.json.gz"
            expanded = Path(directory) / "feed.json"
            with self._client.stream("GET", f"{base}.json.gz") as response:
                response.raise_for_status()
                with compressed.open("wb") as target:
                    for chunk in response.iter_bytes(chunk_size=1024 * 1024):
                        target.write(chunk)
            checksum = hashlib.sha256()
            with gzip.open(compressed, "rb") as source, expanded.open("wb") as target:
                while chunk := source.read(1024 * 1024):
                    checksum.update(chunk)
                    target.write(chunk)
            if checksum.hexdigest().lower() != expected:
                raise InvalidNvdFeed(
                    "NVD feed checksum mismatch; nothing from this snapshot was imported"
                )
            with expanded.open("rb") as source:
                yield (
                    normalize_nvd_vulnerability(item)
                    for item in ijson.items(source, "vulnerabilities.item", use_float=True)
                )


def _metadata_checksum(metadata: str) -> str:
    for line in metadata.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip().lower() == "sha256":
            digest = value.strip().lower()
            if re.fullmatch(r"[0-9a-f]{64}", digest):
                return digest
    raise InvalidNvdFeed("Official NVD metadata has no valid SHA256 digest")
