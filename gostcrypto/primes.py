"""Probabilistic primality test: trial division by small primes, then Miller-Rabin."""

import secrets

from gostcrypto.modular import mod_pow

MILLER_RABIN_ROUNDS = 40

SMALL_PRIMES = tuple(
    n for n in range(2, 1000) if all(n % d for d in range(2, int(n**0.5) + 1))
)


def is_strong_probable_prime(n: int, base: int) -> bool:
    s = ((n - 1) & -(n - 1)).bit_length() - 1
    d = (n - 1) >> s
    x = mod_pow(base, d, n)
    if x in (1, n - 1):
        return True
    for _ in range(s - 1):
        x = x * x % n
        if x == n - 1:
            return True
    return False


def is_probable_prime(n: int, rounds: int = MILLER_RABIN_ROUNDS) -> bool:
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n % p == 0:
            return n == p
    return all(
        is_strong_probable_prime(n, secrets.randbelow(n - 3) + 2) for _ in range(rounds)
    )
