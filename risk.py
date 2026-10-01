"""
Risk engine — QAZIR EREJE NEGIZINDE (rule-based), keiin ML modeline auystyrylady.

MANYZDY: bul faildagi 3 funktsia (score_number, score_url, score_text,
score_transaction) — tugel jүйенің "miy" bolіgi. Modeli uiretilgen sonda
(train_fraud_model.py), tek score_transaction ishindegi logikany
model.predict_proba(...) shakyruyna auystyrasyz, al API (main.py) ozgermeidi.
"""
import re
import datetime as dt
from typing import List, Tuple
from urllib.parse import urlparse

from db import RiskLevel

TRUSTED_DOMAINS = {"kaspi.kz", "halykbank.kz", "egov.kz", "gov.kz", "google.com"}
BRAND_KEYWORDS = ["kaspi", "halyk", "egov", "kazpost"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "cutt.ly"}
SUSPICIOUS_URL_WORDS = re.compile(r"(login|verify|bonus|gift|prize|secure|pay)", re.I)

SCAM_SIGNS = [
    ("Асығыс талап", ["шұғыл", "дереу", "30 минут", "срочно", "немедленно", "в течение"]),
    ("Код / карта деректерін сұрау", ["смс-код", "sms код", "cvv", "пин", "pin", "cvc", "құпия"]),
    ("Ресми емес сілтеме", ["http", "www.", "bit.ly", ".kz/", "tinyurl"]),
    ("«Қауіпсіз шот» схемасы", ["қауіпсіз шот", "безопасный счет", "безопасный счёт"]),
    ("Жалған ұтыс / сыйлық", ["ұтып", "ұтыс", "сыйлық", "выиграл", "приз", "бонус"]),
    ("Ресми органнан болып көрсету", ["полиция", "прокуратура", "қауіпсіздік қызметі",
                                        "служба безопасности", "сот"]),
]


# ---------------------------------------------------------------------------
# NOMIR
# ---------------------------------------------------------------------------
def score_number(report_count: int) -> Tuple[int, RiskLevel]:
    """Shagym sanyna karai 0-100 skor. Nagyz juiede buga qonyrau
    jиiligi, VoIP belgisi de qosylady."""
    if report_count == 0:
        return 5, RiskLevel.safe
    if report_count < 5:
        return 35, RiskLevel.warn
    score = min(100, 40 + report_count * 3)
    return score, RiskLevel.danger


# ---------------------------------------------------------------------------
# SILTEME
# ---------------------------------------------------------------------------
def score_url(raw_url: str) -> Tuple[RiskLevel, List[str]]:
    url = raw_url.strip()
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    if not host or "." not in host:
        return RiskLevel.warn, ["Сілтеме дұрыс форматта емес"]

    if any(host == t or host.endswith("." + t) for t in TRUSTED_DOMAINS):
        return RiskLevel.safe, ["Домен ресми сайттар тізімінде бар", "Күмәнді белгілер табылмады"]

    reasons: List[str] = []
    brand_fake = False
    for b in BRAND_KEYWORDS:
        if b in host and host not in TRUSTED_DOMAINS:
            brand_fake = True
            reasons.append(f"{b} сайтына ұқсас жалған домен ({host})")

    if parsed.scheme != "https":
        reasons.append("Қауіпсіз емес байланыс (HTTPS жоқ)")
    if host in SHORTENERS:
        reasons.append("Қысқартылған сілтеме, артында не тұрғаны белгісіз")
    if SUSPICIOUS_URL_WORDS.search(url):
        reasons.append("Күдікті кілт сөздер бар (login, bonus, verify...)")
    if host.count("-") >= 2 or len(host) > 30:
        reasons.append("Домен тым ұзын немесе сызықшалар көп")

    # TODO (production): WHOIS - domen jasy, Google Safe Browsing API, VirusTotal

    if not reasons:
        return RiskLevel.warn, ["Домен бізге белгісіз, сақ болыңыз"]

    level = RiskLevel.danger if (brand_fake or len(reasons) >= 2) else RiskLevel.warn
    return level, reasons


# ---------------------------------------------------------------------------
# MATIN
# ---------------------------------------------------------------------------
def score_text(text: str) -> Tuple[int, RiskLevel, List[str]]:
    low = text.lower()
    found: List[str] = []
    hit_count = 0
    for title, keywords in SCAM_SIGNS:
        hit = any(k in low for k in keywords)
        if hit:
            found.append(title)
            hit_count += 1

    # TODO (production): kilt sozder ornyna NLP/LLM klassifikator
    score = min(100, hit_count * 30 + (10 if hit_count else 0))
    level = RiskLevel.danger if score >= 60 else RiskLevel.warn if score >= 30 else RiskLevel.safe
    return score, level, found


# ---------------------------------------------------------------------------
# TRANSAKTSIYA  (bul jer keiin train_fraud_model.py modeline auystyrylady)
# ---------------------------------------------------------------------------
def score_transaction(
    amount: float,
    avg_amount: float,
    recipient_new: bool,
    device_new: bool,
    hour: int,
) -> Tuple[int, RiskLevel, List[str]]:
    """
    QAZIR: kol menen jazylgan ereje. avg_amount = paidalanushynyn
    ortasha translation somasy (soñgy 30 kunde).

    KEIIN: osy funktsianyn ishin alystyrasyz:
        import joblib
        model = joblib.load("fraud_model.pkl")
        proba = model.predict_proba([[amount, ...]])[0][1]
        score = int(proba * 100)
    API (main.py) buny bilmeidi, tek score_transaction(...) shakyrady —
    сондықтан ауыстыру endpoint-terge tиmeidi.
    """
    score = 0
    reasons: List[str] = []

    if avg_amount > 0 and amount > avg_amount * 5:
        score += 40
        reasons.append("Сома әдеттегіден 5+ есе көп")
    elif avg_amount > 0 and amount > avg_amount * 2:
        score += 20
        reasons.append("Сома әдеттегіден 2+ есе көп")

    if recipient_new:
        score += 20
        reasons.append("Жаңа алушы")

    if device_new:
        score += 15
        reasons.append("Жаңа құрылғы")

    if hour <= 5 or hour >= 23:
        score += 15
        reasons.append("Түнгі уақыт")

    score = min(100, score)
    level = (
        RiskLevel.danger if score >= 60 else
        RiskLevel.warn if score >= 30 else
        RiskLevel.safe
    )
    return score, level, reasons


def current_hour() -> int:
    return dt.datetime.utcnow().hour
