"""Recovery codes: ten one-time codes shown once; only Streebog-512 hashes are stored."""

import re
import secrets

from app.db import get_db
from gostcrypto.streebog import streebog512

ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
CODE_COUNT = 10
CODE_LENGTH = 10


def normalize(code: str) -> str:
    return re.sub(r"[\s-]", "", code).upper()


def looks_like_recovery_code(code: str) -> bool:
    return len(normalize(code)) == CODE_LENGTH


def recovery_hash(user_id: int, code: str) -> bytes:
    return streebog512(f"{user_id}:recovery:{normalize(code)}".encode())


def issue_recovery_codes(user_id: int) -> list[str]:
    codes = [
        "".join(secrets.choice(ALPHABET) for _ in range(CODE_LENGTH))
        for _ in range(CODE_COUNT)
    ]
    db = get_db()
    with db.transaction():
        db.execute("DELETE FROM recovery_codes WHERE user_id = %s", (user_id,))
        db.cursor().executemany(
            "INSERT INTO recovery_codes (user_id, code_hash) VALUES (%s, %s)",
            [(user_id, recovery_hash(user_id, code)) for code in codes],
        )
    half = CODE_LENGTH // 2
    return [f"{code[:half]}-{code[half:]}" for code in codes]


def consume_recovery_code(user_id: int, code: str) -> bool:
    row = (
        get_db()
        .execute(
            "UPDATE recovery_codes SET used_at = now()"
            " WHERE user_id = %s AND code_hash = %s AND used_at IS NULL RETURNING id",
            (user_id, recovery_hash(user_id, code)),
        )
        .fetchone()
    )
    return row is not None


def remaining_recovery_codes(user_id: int) -> int:
    (count,) = (
        get_db()
        .execute(
            "SELECT count(*) FROM recovery_codes WHERE user_id = %s AND used_at IS NULL",
            (user_id,),
        )
        .fetchone()
    )
    return count
