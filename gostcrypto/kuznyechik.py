"""Kuznyechik block cipher, GOST 34.12-2018, section 4.

Blocks and keys are bytes in the order the standard writes its hex vectors:
byte 0 of a block is a_15, byte 15 is a_0.
"""

from gostcrypto.streebog import PI

BLOCK_BYTES = 16
KEY_BYTES = 32
FIELD_POLYNOMIAL = 0x1C3

PI_INVERSE = tuple(PI.index(value) for value in range(256))

# GOST 34.12-2018, 4.1.2: coefficients of a_15, ..., a_0
L_COEFFICIENTS = (148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1)


def gf_multiply(a: int, b: int) -> int:
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= FIELD_POLYNOMIAL
        b >>= 1
    return result


def x_transform(k: bytes, a: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(k, a, strict=True))


def s_transform(a: bytes) -> bytes:
    return bytes(PI[x] for x in a)


def s_inverse(a: bytes) -> bytes:
    return bytes(PI_INVERSE[x] for x in a)


def linear_l(a: bytes) -> int:
    result = 0
    for coefficient, x in zip(L_COEFFICIENTS, a, strict=True):
        result ^= gf_multiply(coefficient, x)
    return result


def r_transform(a: bytes) -> bytes:
    return bytes([linear_l(a)]) + a[:-1]


def r_inverse(a: bytes) -> bytes:
    shifted = a[1:]
    return shifted + bytes([linear_l(shifted + a[:1])])


def l_transform(a: bytes) -> bytes:
    for _ in range(16):
        a = r_transform(a)
    return a


def l_inverse(a: bytes) -> bytes:
    for _ in range(16):
        a = r_inverse(a)
    return a


def lsx(k: bytes, a: bytes) -> bytes:
    return l_transform(s_transform(x_transform(k, a)))


def f_transform(k: bytes, a1: bytes, a0: bytes) -> tuple[bytes, bytes]:
    return x_transform(lsx(k, a1), a0), a1


ROUND_CONSTANTS = tuple(
    l_transform(i.to_bytes(BLOCK_BYTES, "big")) for i in range(1, 33)
)


def round_keys(key: bytes) -> list[bytes]:
    require_length(key, KEY_BYTES, "key")
    keys = [key[:BLOCK_BYTES], key[BLOCK_BYTES:]]
    for i in range(4):
        a1, a0 = keys[-2], keys[-1]
        for constant in ROUND_CONSTANTS[8 * i : 8 * i + 8]:
            a1, a0 = f_transform(constant, a1, a0)
        keys += [a1, a0]
    return keys


def encrypt_block(key: bytes, block: bytes) -> bytes:
    require_length(block, BLOCK_BYTES, "block")
    keys = round_keys(key)
    for k in keys[:-1]:
        block = lsx(k, block)
    return x_transform(keys[-1], block)


def decrypt_block(key: bytes, block: bytes) -> bytes:
    require_length(block, BLOCK_BYTES, "block")
    keys = round_keys(key)
    block = x_transform(keys[-1], block)
    for k in reversed(keys[:-1]):
        block = x_transform(k, s_inverse(l_inverse(block)))
    return block


def require_length(value: bytes, length: int, name: str) -> None:
    if len(value) != length:
        raise ValueError(f"{name} must be {length} bytes, got {len(value)}")
