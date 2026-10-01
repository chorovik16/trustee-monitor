import json
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class Domain(Base):
    __tablename__ = "domains"

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain_name = Column(String(255), unique=True, nullable=False, index=True)
    source = Column(String(64), default="certstream")  # certstream, mutation, manual
    first_seen_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_checked_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    current_risk_score = Column(Integer, default=0)
    current_status = Column(String(64), default="unknown")  # clean, parked, suspicious, active_phishing, dormant

    checks = relationship(
        "DomainCheck",
        back_populates="domain",
        cascade="all, delete-orphan",
        order_by="desc(DomainCheck.checked_at)"
    )

    def __repr__(self):
        return f"<Domain(name={self.domain_name}, score={self.current_risk_score}, status={self.current_status})>"


class DomainCheck(Base):
    __tablename__ = "domain_checks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain_id = Column(Integer, ForeignKey("domains.id", ondelete="CASCADE"), nullable=False, index=True)
    checked_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    risk_score = Column(Integer, default=0)
    status = Column(String(64), default="unknown")
    ip_address = Column(String(128), nullable=True)
    mx_records = Column(Text, nullable=True)  # comma-separated or json string
    http_status = Column(Integer, nullable=True)
    ssl_issuer = Column(String(255), nullable=True)
    ssl_age_days = Column(Integer, nullable=True)
    matched_keywords = Column(Text, nullable=True)  # json string of matched words
    triggers = Column(Text, nullable=True)          # json string of threat triggers
    raw_details = Column(Text, nullable=True)

    domain = relationship("Domain", back_populates="checks")

    @property
    def triggers_list(self):
        if not self.triggers:
            return []
        try:
            return json.loads(self.triggers)
        except Exception:
            return [self.triggers]

    @property
    def keywords_list(self):
        if not self.matched_keywords:
            return []
        try:
            return json.loads(self.matched_keywords)
        except Exception:
            return [self.matched_keywords]

    def __repr__(self):
        return f"<DomainCheck(domain_id={self.domain_id}, score={self.risk_score}, checked_at={self.checked_at})>"
