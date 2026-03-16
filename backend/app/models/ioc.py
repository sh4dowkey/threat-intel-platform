from datetime import datetime, timezone
from sqlalchemy import String, Integer, Boolean, DateTime, JSON
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class IOCRecord(Base):
    __tablename__ = "ioc_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ioc: Mapped[str] = mapped_column(String(256), index=True, nullable=False)
    ioc_type: Mapped[str] = mapped_column(String(16), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    verdict: Mapped[str] = mapped_column(String(16), default="unknown")
    vt_malicious: Mapped[int] = mapped_column(Integer, default=0)
    vt_suspicious: Mapped[int] = mapped_column(Integer, default=0)
    vt_harmless: Mapped[int] = mapped_column(Integer, default=0)
    vt_total_engines: Mapped[int] = mapped_column(Integer, default=0)
    vt_reputation: Mapped[int] = mapped_column(Integer, default=0)
    vt_tags: Mapped[list] = mapped_column(JSON, default=list)
    vt_country: Mapped[str | None] = mapped_column(String(8), nullable=True)
    vt_as_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    vt_error: Mapped[str | None] = mapped_column(String(128), nullable=True)
    abuse_confidence_score: Mapped[int] = mapped_column(Integer, default=0)
    abuse_total_reports: Mapped[int] = mapped_column(Integer, default=0)
    abuse_num_reporters: Mapped[int] = mapped_column(Integer, default=0)
    abuse_isp: Mapped[str | None] = mapped_column(String(128), nullable=True)
    abuse_usage_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    abuse_last_reported: Mapped[str | None] = mapped_column(String(64), nullable=True)
    abuse_is_whitelisted: Mapped[bool] = mapped_column(Boolean, default=False)
    abuse_error: Mapped[str | None] = mapped_column(String(128), nullable=True)
    sources_queried: Mapped[list] = mapped_column(JSON, default=list)
    enrichment_errors: Mapped[list] = mapped_column(JSON, default=list)
    looked_up_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    lookup_count: Mapped[int] = mapped_column(Integer, default=1)