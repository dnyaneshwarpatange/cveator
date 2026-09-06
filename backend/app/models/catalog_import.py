from datetime import datetime

from sqlalchemy import DateTime, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class CatalogImport(Base):
    """Durable bootstrap checkpoint; page writes and progress commit together."""

    __tablename__ = "catalog_imports"

    source: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="running")
    next_start_index: Mapped[int] = mapped_column(nullable=False, default=0)
    total_results: Mapped[int] = mapped_column(nullable=False, default=0)
    products_upserted: Mapped[int] = mapped_column(nullable=False, default=0)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    error: Mapped[str | None] = mapped_column(Text)
