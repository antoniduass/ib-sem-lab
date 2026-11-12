"""Modular arithmetic for RSA and GOST 34.10, written by hand (SPEC ТП-1, ОВ-17)."""


def mod_pow(base: int, exponent: int, modulus: int) -> int:
    if exponent < 0 or modulus < 1:
        raise ValueError("exponent must be >= 0 and modulus >= 1")
    result = 1
    base %= modulus
    for bit in bin(exponent)[2:]:
        result = result * result % modulus
        if bit == "1":
            result = result * base % modulus
    return result


def mod_inverse(value: int, modulus: int) -> int:
    if modulus < 1:
        raise ValueError("modulus must be >= 1")
    old_r, r = value % modulus, modulus
    old_s, s = 1, 0
    while r:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
    if old_r != 1:
        raise ValueError("value is not invertible modulo modulus")
    return old_s % modulus
