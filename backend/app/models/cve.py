from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Cve(Base):
    __tablename__ = "cves"

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    source_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    normalized_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )
    cvss_score: Mapped[float | None] = mapped_column(Float)
    epss_score: Mapped[float | None] = mapped_column(Float)
    is_kev: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (Index("ix_cves_is_kev_cvss_score", "is_kev", "cvss_score"),)


class CveChange(Base):
    __tablename__ = "cve_changes"

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[int] = mapped_column(ForeignKey("cves.id", ondelete="CASCADE"), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    changes: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    source_modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (Index("ix_cve_changes_cve_observed", "cve_id", "observed_at"),)


class IngestionCursor(Base):
    __tablename__ = "ingestion_cursors"

    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    high_watermark: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (UniqueConstraint("source", name="uq_ingestion_cursors_source"),)
