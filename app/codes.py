"""One-time codes sent by email. Only the Streebog-512 hash of a code is stored."""

import secrets
from datetime import timedelta

from app.db import get_db
from gostcrypto.streebog import streebog512

CODE_LIFETIME = timedelta(minutes=10)
CODE_DIGITS = 6


def code_hash(user_id: int, code: str) -> bytes:
    return streebog512(f"{user_id}:{code}".encode())


def issue_code(user_id: int, purpose: str) -> str:
    code = f"{secrets.randbelow(10**CODE_DIGITS):0{CODE_DIGITS}d}"
    db = get_db()
    with db.transaction():
        db.execute(
            "UPDATE one_time_codes SET used_at = now()"
            " WHERE user_id = %s AND purpose = %s AND used_at IS NULL",
            (user_id, purpose),
        )
        db.execute(
            "INSERT INTO one_time_codes (user_id, purpose, code_hash, expires_at)"
            " VALUES (%s, %s, %s, now() + %s)",
            (user_id, purpose, code_hash(user_id, code), CODE_LIFETIME),
        )
    return code


def consume_code(user_id: int, purpose: str, code: str) -> bool:
    row = (
        get_db()
        .execute(
            "UPDATE one_time_codes SET used_at = now()"
            " WHERE user_id = %s AND purpose = %s AND code_hash = %s"
            " AND used_at IS NULL AND expires_at > now() RETURNING id",
            (user_id, purpose, code_hash(user_id, code)),
        )
        .fetchone()
    )
    return row is not None
