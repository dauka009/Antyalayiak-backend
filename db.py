"""
Deректer bazasy: qosylu + ORM modelder.

Default: SQLite (dev ushin, ornatudy talap etpeidi).
Production ushin: DATABASE_URL ortalyk aynymalysyn PostgreSQL-ge auystyryngyz, mysaly:
    export DATABASE_URL="postgresql://user:pass@localhost:5432/qalqan"
"""
import os
import enum
import datetime as dt

from sqlalchemy import (
    create_engine, Column, Integer, String, Boolean, DateTime,
    ForeignKey, Enum, BigInteger, Float, Text, UniqueConstraint
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, Session

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./qalqan.db")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# ROLDER
# ---------------------------------------------------------------------------
class Role(str, enum.Enum):
    user = "user"          # kadimgi paidalanushy (mobil kosymsha)
    analyst = "analyst"    # bank/qauipsizdik analitigi (admin panel)


class RiskLevel(str, enum.Enum):
    safe = "safe"
    warn = "warn"
    danger = "danger"


# ---------------------------------------------------------------------------
# MODELDER
# ---------------------------------------------------------------------------
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    phone = Column(String(20), unique=True, nullable=False, index=True)
    name = Column(String(100), default="")
    pin_hash = Column(String(255), nullable=True)
    role = Column(Enum(Role), default=Role.user, nullable=False)
    monthly_limit = Column(Integer, default=500_000)  # tenge, kumandi bolatyn shek
    created_at = Column(DateTime, default=dt.datetime.utcnow)

    transactions = relationship("Transaction", back_populates="user")
    reports = relationship("NumberReport", back_populates="reporter")


class OtpCode(Base):
    """SMS-kod. Nagyz SMS provaider (mysaly Mobizon, SMSC.kz) osy kestege jazyp,
    /auth/verify-otp arqyly tekseriledi."""
    __tablename__ = "otp_codes"

    id = Column(Integer, primary_key=True)
    phone = Column(String(20), index=True, nullable=False)
    code = Column(String(6), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)


class PhoneNumber(Base):
    """Ortak nomir bazasy: shagymdar jinaktalgan sayyn risk_score esepteledi."""
    __tablename__ = "phone_numbers"

    id = Column(Integer, primary_key=True)
    phone = Column(String(20), unique=True, index=True, nullable=False)
    report_count = Column(Integer, default=0)
    risk_score = Column(Integer, default=0)       # 0-100
    risk_level = Column(Enum(RiskLevel), default=RiskLevel.safe)
    top_category = Column(String(50), default="")
    first_seen = Column(DateTime, default=dt.datetime.utcnow)
    last_report_at = Column(DateTime, nullable=True)

    reports = relationship("NumberReport", back_populates="number")


class NumberReport(Base):
    __tablename__ = "number_reports"

    id = Column(Integer, primary_key=True)
    number_id = Column(Integer, ForeignKey("phone_numbers.id"), nullable=False)
    reporter_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    category = Column(String(50), nullable=False)   # "Жалған банк", "Қауіпсіз шот" т.б.
    comment = Column(Text, default="")
    created_at = Column(DateTime, default=dt.datetime.utcnow)

    number = relationship("PhoneNumber", back_populates="reports")
    reporter = relationship("User", back_populates="reports")

    __table_args__ = (UniqueConstraint("number_id", "reporter_id", name="one_report_per_user"),)


class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    amount = Column(Float, nullable=False)
    recipient = Column(String(100), default="")
    city = Column(String(50), default="")
    device_new = Column(Boolean, default=False)
    recipient_new = Column(Boolean, default=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow)

    risk_score = Column(Integer, default=0)          # 0-100, risk.py eseptейди
    risk_level = Column(Enum(RiskLevel), default=RiskLevel.safe)
    reasons = Column(Text, default="[]")              # JSON-tizim
    status = Column(String(20), default="pending")    # pending / confirmed / blocked
    reviewed_by_analyst = Column(Boolean, default=False)

    user = relationship("User", back_populates="transactions")


class LinkCheck(Base):
    __tablename__ = "link_checks"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    url = Column(String(500), nullable=False)
    risk_level = Column(Enum(RiskLevel), default=RiskLevel.safe)
    reasons = Column(Text, default="[]")
    created_at = Column(DateTime, default=dt.datetime.utcnow)


def init_db():
    Base.metadata.create_all(bind=engine)
