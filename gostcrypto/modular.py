"""Modular arithmetic for RSA and GOST 34.10, written by hand (SPEC ТП-1, ОВ-17)."""

WINDOW_BITS = 5


def mod_pow(base: int, exponent: int, modulus: int) -> int:
    if exponent < 0 or modulus < 1:
        raise ValueError("exponent must be >= 0 and modulus >= 1")
    window_mask = (1 << WINDOW_BITS) - 1
    powers = [1 % modulus]
    for _ in range(window_mask):
        powers.append(powers[-1] * base % modulus)
    result = 1 % modulus
    top_shift = (exponent.bit_length() - 1) // WINDOW_BITS * WINDOW_BITS
    for shift in range(top_shift, -1, -WINDOW_BITS):
        for _ in range(WINDOW_BITS):
            result = result * result % modulus
        window = (exponent >> shift) & window_mask
        if window:
            result = result * powers[window] % modulus
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
