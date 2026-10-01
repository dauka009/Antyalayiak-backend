"""API-ga kiretin / shygatyn derekter piшini (Pydantic)."""
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field

from db import Role, RiskLevel


# ---------- Auth ----------
class RegisterRequest(BaseModel):
    phone: str = Field(..., examples=["+77771234567"])


class VerifyOtpRequest(BaseModel):
    phone: str
    code: str
    pin: str = Field(..., min_length=4, max_length=4)


class LoginRequest(BaseModel):
    phone: str
    pin: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: Role


class UserOut(BaseModel):
    id: int
    phone: str
    name: str
    role: Role
    monthly_limit: int

    class Config:
        from_attributes = True


# ---------- Number check ----------
class NumberCheckResponse(BaseModel):
    phone: str
    risk_level: RiskLevel
    risk_score: int
    report_count: int
    top_category: str = ""


class ReportRequest(BaseModel):
    phone: str
    category: str
    comment: str = ""


class ReportResponse(BaseModel):
    ok: bool
    phone: str
    new_report_count: int
    new_risk_level: RiskLevel


# ---------- Link check ----------
class LinkCheckRequest(BaseModel):
    url: str


class LinkCheckResponse(BaseModel):
    url: str
    risk_level: RiskLevel
    reasons: List[str]


# ---------- Text check ----------
class TextCheckRequest(BaseModel):
    text: str


class TextCheckResponse(BaseModel):
    risk_level: RiskLevel
    score: int
    signs: List[str]


# ---------- Transactions ----------
class TransactionCreate(BaseModel):
    amount: float
    recipient: str = ""
    city: str = ""
    device_new: bool = False
    recipient_new: bool = False


class TransactionOut(BaseModel):
    id: int
    amount: float
    recipient: str
    city: str
    risk_score: int
    risk_level: RiskLevel
    reasons: List[str]
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


class TransactionDecision(BaseModel):
    action: str  # "confirm" | "block"


# ---------- Analyst / admin ----------
class FlaggedTransactionOut(TransactionOut):
    user_phone: str
