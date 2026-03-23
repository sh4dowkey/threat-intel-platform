from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, Boolean, DateTime, JSON
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Network context
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # ML scores
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    verdict: Mapped[str] = mapped_column(String(16), default="unknown", index=True)
    attack_class: Mapped[str] = mapped_column(String(64), default="unknown")
    attack_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False)

    # LLM explanation
    summary: Mapped[str] = mapped_column(String(512), default="")
    what_is_happening: Mapped[str] = mapped_column(String(1024), default="")
    why_flagged: Mapped[str] = mapped_column(String(512), default="")
    potential_impact: Mapped[str] = mapped_column(String(512), default="")
    recommended_action: Mapped[str] = mapped_column(String(1024), default="")
    false_positive_likelihood: Mapped[str] = mapped_column(String(256), default="")
    severity: Mapped[str] = mapped_column(String(16), default="low", index=True)
    explanation_cached: Mapped[bool] = mapped_column(Boolean, default=False)

    # MITRE ATT&CK
    mitre_tactic_id: Mapped[str] = mapped_column(String(16), default="")
    mitre_tactic_name: Mapped[str] = mapped_column(String(64), default="")
    mitre_technique_id: Mapped[str] = mapped_column(String(16), default="")
    mitre_technique_name: Mapped[str] = mapped_column(String(128), default="")
    mitre_technique_url: Mapped[str] = mapped_column(String(256), default="")

    # SHAP top features (stored as JSON array)
    top_features: Mapped[list] = mapped_column(JSON, default=list)

    # Analyst workflow
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
