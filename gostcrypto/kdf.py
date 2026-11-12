"""HMAC_GOSTR3411_2012_512 (RFC 7836, 4.1.2; RFC 2104) and PBKDF2 on it (RFC 9337, section 4)."""

from gostcrypto.streebog import streebog512

HASH_BLOCK_BYTES = 64
DIGEST_BYTES = 64


def hmac_streebog512(key: bytes, data: bytes) -> bytes:
    if len(key) > HASH_BLOCK_BYTES:
        key = streebog512(key)
    key = key.ljust(HASH_BLOCK_BYTES, b"\x00")
    inner = streebog512(bytes(byte ^ 0x36 for byte in key) + data)
    return streebog512(bytes(byte ^ 0x5C for byte in key) + inner)


def pbkdf2_streebog512(
    password: bytes, salt: bytes, iterations: int, length: int
) -> bytes:
    if iterations < 1 or length < 1:
        raise ValueError("iterations and length must be positive")
    if length > (2**32 - 1) * DIGEST_BYTES:
        raise ValueError("derived key too long")
    blocks = []
    for index in range(1, -(-length // DIGEST_BYTES) + 1):
        u = hmac_streebog512(password, salt + index.to_bytes(4, "big"))
        block = int.from_bytes(u, "big")
        for _ in range(iterations - 1):
            u = hmac_streebog512(password, u)
            block ^= int.from_bytes(u, "big")
        blocks.append(block.to_bytes(DIGEST_BYTES, "big"))
    return b"".join(blocks)[:length]
