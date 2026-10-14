import json
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import declarative_base, relationship
Base = declarative_base()

class Domain(Base):
    __tablename__ = 'domains'
    id = Column(Integer, primary_key=True, autoincrement=True)
    domain_name = Column(String(255), unique=True, nullable=False, index=True)
    source = Column(String(64), default='certstream')
    first_seen_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_checked_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    current_risk_score = Column(Integer, default=0)
    current_status = Column(String(64), default='unknown')
    checks = relationship('DomainCheck', back_populates='domain', cascade='all, delete-orphan', order_by='desc(DomainCheck.checked_at)')

    def __repr__(self):
        return f'<Domain(name={self.domain_name}, score={self.current_risk_score}, status={self.current_status})>'

class DomainCheck(Base):
    __tablename__ = 'domain_checks'
    id = Column(Integer, primary_key=True, autoincrement=True)
    domain_id = Column(Integer, ForeignKey('domains.id', ondelete='CASCADE'), nullable=False, index=True)
    checked_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    risk_score = Column(Integer, default=0)
    status = Column(String(64), default='unknown')
    ip_address = Column(String(128), nullable=True)
    mx_records = Column(Text, nullable=True)
    http_status = Column(Integer, nullable=True)
    ssl_issuer = Column(String(255), nullable=True)
    ssl_age_days = Column(Integer, nullable=True)
    matched_keywords = Column(Text, nullable=True)
    triggers = Column(Text, nullable=True)
    raw_details = Column(Text, nullable=True)
    domain = relationship('Domain', back_populates='checks')

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
        return f'<DomainCheck(domain_id={self.domain_id}, score={self.risk_score}, checked_at={self.checked_at})>'

class Whitelist(Base):
    __tablename__ = 'whitelist'
    id = Column(Integer, primary_key=True, autoincrement=True)
    domain_name = Column(String(255), unique=True, nullable=False, index=True)
    added_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    added_by = Column(String(128), default='telegram_admin')
    comment = Column(String(255), nullable=True)

    def __repr__(self):
        return f'<Whitelist(domain={self.domain_name}, added_by={self.added_by})>'
