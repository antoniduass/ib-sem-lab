import secrets

from gostcrypto.kdf import pbkdf2_streebog512

SALT_BYTES = 16
HASH_BYTES = 64


def derive_password_hash(password: str, salt: bytes, iterations: int) -> bytes:
    return pbkdf2_streebog512(password.encode(), salt, iterations, HASH_BYTES)


def hash_password(password: str, iterations: int) -> tuple[bytes, bytes]:
    salt = secrets.token_bytes(SALT_BYTES)
    return salt, derive_password_hash(password, salt, iterations)
