"""
Qalqan Backend API
===================
Iske kosu:
    pip install -r requirements.txt
    uvicorn main:app --reload

Swagger dokumentatsia avtomaty turde: http://127.0.0.1:8000/docs
"""
import json
import random
import datetime as dt
from typing import List

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func

from db import (
    get_db, init_db, User, Role, RiskLevel, OtpCode,
    PhoneNumber, NumberReport, Transaction, LinkCheck,
)
import schemas as sc
import security as sec
import risk

app = FastAPI(title="Qalqan API", version="0.1.0")

# DEV ushin barlyk domenge ashyk. Production-da naqty domenmen shektengiz.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    init_db()


# ===========================================================================
# AUTH
# ===========================================================================
@app.post("/auth/register", tags=["auth"])
def register(req: sc.RegisterRequest, db: Session = Depends(get_db)):
    """Telefon nomirin registratsiyadan otkizu, SMS-kod jiberu (DEV: konsolge shygady)."""
    existing = db.query(User).filter(User.phone == req.phone).first()
    if existing and existing.pin_hash:
        raise HTTPException(400, "Бұл нөмір тіркелген, кіру арқылы жалғастырыңыз")

    code = f"{random.randint(0, 999999):06d}"
    otp = OtpCode(
        phone=req.phone, code=code,
        expires_at=dt.datetime.utcnow() + dt.timedelta(minutes=5),
    )
    db.add(otp)
    db.commit()

    # TODO (production): naqty SMS provaider (Mobizon, SMSC.kz, т.б.) arqyly jiberu
    print(f"[DEV SMS] {req.phone} -> kod: {code}")

    return {"ok": True, "message": "SMS-код жіберілді", "dev_code": code}


@app.post("/auth/verify-otp", response_model=sc.TokenResponse, tags=["auth"])
def verify_otp(req: sc.VerifyOtpRequest, db: Session = Depends(get_db)):
    otp = (
        db.query(OtpCode)
        .filter(OtpCode.phone == req.phone, OtpCode.code == req.code, OtpCode.used == False)  # noqa: E712
        .order_by(OtpCode.id.desc())
        .first()
    )
    if not otp or otp.expires_at < dt.datetime.utcnow():
        raise HTTPException(400, "Код қате немесе мерзімі өтті")

    otp.used = True

    user = db.query(User).filter(User.phone == req.phone).first()
    if not user:
        user = User(phone=req.phone, role=Role.user)
        db.add(user)
    user.pin_hash = sec.hash_pin(req.pin)
    db.commit()
    db.refresh(user)

    token = sec.create_access_token(user.id, user.role)
    return sc.TokenResponse(access_token=token, role=user.role)


@app.post("/auth/login", response_model=sc.TokenResponse, tags=["auth"])
def login(req: sc.LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.phone == req.phone).first()
    if not user or not user.pin_hash or not sec.verify_pin(req.pin, user.pin_hash):
        raise HTTPException(401, "Нөмір немесе PIN қате")
    token = sec.create_access_token(user.id, user.role)
    return sc.TokenResponse(access_token=token, role=user.role)


@app.get("/auth/me", response_model=sc.UserOut, tags=["auth"])
def me(user: User = Depends(sec.get_current_user)):
    return user


# ===========================================================================
# NOMIR TEKSERU
# ===========================================================================
@app.get("/check-number", response_model=sc.NumberCheckResponse, tags=["anti-scam"])
def check_number(phone: str, db: Session = Depends(get_db)):
    entry = db.query(PhoneNumber).filter(PhoneNumber.phone == phone).first()
    if not entry:
        return sc.NumberCheckResponse(
            phone=phone, risk_level=RiskLevel.safe, risk_score=5, report_count=0
        )
    return sc.NumberCheckResponse(
        phone=phone, risk_level=entry.risk_level, risk_score=entry.risk_score,
        report_count=entry.report_count, top_category=entry.top_category or "",
    )


@app.post("/report", response_model=sc.ReportResponse, tags=["anti-scam"])
def report_number(
    req: sc.ReportRequest,
    db: Session = Depends(get_db),
    user: User = Depends(sec.get_current_user),
):
    entry = db.query(PhoneNumber).filter(PhoneNumber.phone == req.phone).first()
    if not entry:
        entry = PhoneNumber(phone=req.phone)
        db.add(entry)
        db.flush()

    already = (
        db.query(NumberReport)
        .filter(NumberReport.number_id == entry.id, NumberReport.reporter_id == user.id)
        .first()
    )
    if already:
        raise HTTPException(400, "Сіз бұл нөмірге бұрын шағым жасағансыз")

    db.add(NumberReport(
        number_id=entry.id, reporter_id=user.id,
        category=req.category, comment=req.comment,
    ))

    entry.report_count += 1
    entry.last_report_at = dt.datetime.utcnow()
    entry.risk_score, entry.risk_level = risk.score_number(entry.report_count)

    # eñ jиi kezdesken kategoriyany esepteu
    top = (
        db.query(NumberReport.category, func.count(NumberReport.id).label("c"))
        .filter(NumberReport.number_id == entry.id)
        .group_by(NumberReport.category)
        .order_by(func.count(NumberReport.id).desc())
        .first()
    )
    entry.top_category = top[0] if top else ""

    db.commit()
    return sc.ReportResponse(
        ok=True, phone=req.phone,
        new_report_count=entry.report_count, new_risk_level=entry.risk_level,
    )


# ===========================================================================
# SILTEME / MATIN
# ===========================================================================
@app.post("/check-url", response_model=sc.LinkCheckResponse, tags=["anti-scam"])
def check_url(
    req: sc.LinkCheckRequest,
    db: Session = Depends(get_db),
    user: User = Depends(sec.get_current_user),
):
    level, reasons = risk.score_url(req.url)
    db.add(LinkCheck(
        user_id=user.id, url=req.url,
        risk_level=level, reasons=json.dumps(reasons, ensure_ascii=False),
    ))
    db.commit()
    return sc.LinkCheckResponse(url=req.url, risk_level=level, reasons=reasons)


@app.post("/check-text", response_model=sc.TextCheckResponse, tags=["anti-scam"])
def check_text(req: sc.TextCheckRequest):
    score, level, signs = risk.score_text(req.text)
    return sc.TextCheckResponse(risk_level=level, score=score, signs=signs)


# ===========================================================================
# TRANSAKTSIALAR
# ===========================================================================
@app.post("/transactions", response_model=sc.TransactionOut, tags=["transactions"])
def create_transaction(
    req: sc.TransactionCreate,
    db: Session = Depends(get_db),
    user: User = Depends(sec.get_current_user),
):
    avg = (
        db.query(func.avg(Transaction.amount))
        .filter(Transaction.user_id == user.id)
        .scalar()
    ) or 0.0

    score, level, reasons = risk.score_transaction(
        amount=req.amount, avg_amount=avg,
        recipient_new=req.recipient_new, device_new=req.device_new,
        hour=risk.current_hour(),
    )

    tx = Transaction(
        user_id=user.id, amount=req.amount, recipient=req.recipient, city=req.city,
        device_new=req.device_new, recipient_new=req.recipient_new,
        risk_score=score, risk_level=level, reasons=json.dumps(reasons, ensure_ascii=False),
        status="pending" if level != RiskLevel.safe else "confirmed",
    )
    db.add(tx)
    db.commit()
    db.refresh(tx)

    return _tx_to_out(tx)


@app.get("/transactions", response_model=List[sc.TransactionOut], tags=["transactions"])
def list_transactions(db: Session = Depends(get_db), user: User = Depends(sec.get_current_user)):
    rows = (
        db.query(Transaction)
        .filter(Transaction.user_id == user.id)
        .order_by(Transaction.created_at.desc())
        .all()
    )
    return [_tx_to_out(t) for t in rows]


@app.post("/transactions/{tx_id}/decide", response_model=sc.TransactionOut, tags=["transactions"])
def decide_transaction(
    tx_id: int, req: sc.TransactionDecision,
    db: Session = Depends(get_db), user: User = Depends(sec.get_current_user),
):
    tx = db.query(Transaction).filter(Transaction.id == tx_id, Transaction.user_id == user.id).first()
    if not tx:
        raise HTTPException(404, "Транзакция табылмады")
    if req.action not in ("confirm", "block"):
        raise HTTPException(400, "action 'confirm' немесе 'block' болу керек")
    tx.status = "confirmed" if req.action == "confirm" else "blocked"
    db.commit()
    db.refresh(tx)
    return _tx_to_out(tx)


def _tx_to_out(tx: Transaction) -> sc.TransactionOut:
    return sc.TransactionOut(
        id=tx.id, amount=tx.amount, recipient=tx.recipient, city=tx.city,
        risk_score=tx.risk_score, risk_level=tx.risk_level,
        reasons=json.loads(tx.reasons or "[]"),
        status=tx.status, created_at=tx.created_at,
    )


# ===========================================================================
# ANALYST / ADMIN (rol = analyst gana kire alady)
# ===========================================================================
@app.get(
    "/admin/flagged",
    response_model=List[sc.FlaggedTransactionOut],
    tags=["admin"],
    dependencies=[Depends(sec.require_role(Role.analyst))],
)
def flagged_transactions(db: Session = Depends(get_db)):
    """Tek 'analyst' rolindegi paidalanushy kore alady (bank / qauipsizdik komandasy)."""
    rows = (
        db.query(Transaction, User.phone)
        .join(User, Transaction.user_id == User.id)
        .filter(Transaction.risk_level != RiskLevel.safe)
        .order_by(Transaction.created_at.desc())
        .limit(200)
        .all()
    )
    out = []
    for tx, phone in rows:
        base = _tx_to_out(tx)
        out.append(sc.FlaggedTransactionOut(**base.model_dump(), user_phone=phone))
    return out


@app.post(
    "/admin/make-analyst/{user_id}",
    tags=["admin"],
    dependencies=[Depends(sec.require_role(Role.analyst))],
)
def make_analyst(user_id: int, db: Session = Depends(get_db)):
    """Basqa paidalanushyga analyst roli beru (tek analyst oziniki bere alady)."""
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(404, "Пайдаланушы табылмады")
    target.role = Role.analyst
    db.commit()
    return {"ok": True, "user_id": user_id, "role": "analyst"}


@app.get("/health", tags=["system"])
def health():
    return {"status": "ok"}
