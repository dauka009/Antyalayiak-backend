"""
Birinshi analyst (admin) paidalanushyny jasau.

/admin/make-analyst endpoint-i tek analyst-ke gana ashyk, sondyktan
BIRINSHI analystti osy skript arkyly tikelei bazaga qosamyz.

Qoldanu:
    python seed_admin.py +77001234567 1234
"""
import sys
from db import SessionLocal, User, Role, init_db
import security as sec


def main():
    if len(sys.argv) != 3:
        print("Qoldanu: python seed_admin.py <telefon> <PIN(4 tanba)>")
        sys.exit(1)

    phone, pin = sys.argv[1], sys.argv[2]
    init_db()
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.phone == phone).first()
        if not user:
            user = User(phone=phone)
            db.add(user)
        user.pin_hash = sec.hash_pin(pin)
        user.role = Role.analyst
        user.name = "Analyst"
        db.commit()
        print(f"OK: {phone} endi 'analyst' roline ie (PIN: {pin})")
    finally:
        db.close()


if __name__ == "__main__":
    main()
