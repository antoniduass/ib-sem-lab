"""RSA: key generation, RSAES-PKCS1-v1_5 (RFC 8017, 7.2) and CRT decryption (RFC 8017, 5.1.2).

Usage: python -m gostcrypto.rsa <private_key.json> [modulus_bits]
"""

import json
import math
import os
import secrets
import sys
import time
from functools import cache
from multiprocessing import Pool
from typing import NamedTuple

from gostcrypto.modular import mod_inverse, mod_pow
from gostcrypto.primes import is_probable_prime

PUBLIC_EXPONENT = 65537
MODULUS_BITS = 32768
SIEVE_LIMIT = 1_000_000
SEARCH_WINDOW = 1 << 16
# Candidates are random and already sieved; 5 rounds bound the error far below 2^-100 at these sizes.
FINAL_ROUNDS = 5
PKCS1_OVERHEAD = 11


class PublicKey(NamedTuple):
    n: int
    e: int


class PrivateKey(NamedTuple):
    n: int
    e: int
    d: int
    p: int
    q: int
    dp: int
    dq: int
    q_inverse: int

    @property
    def public_key(self) -> PublicKey:
        return PublicKey(self.n, self.e)


@cache
def small_odd_primes() -> tuple[int, ...]:
    flags = bytearray([1]) * SIEVE_LIMIT
    flags[0:2] = b"\x00\x00"
    for i in range(2, math.isqrt(SIEVE_LIMIT) + 1):
        if flags[i]:
            flags[i * i :: i] = bytes(len(range(i * i, SIEVE_LIMIT, i)))
    return tuple(i for i in range(3, SIEVE_LIMIT) if flags[i])


def sieve_window(start: int) -> bytearray:
    survivors = bytearray([1]) * SEARCH_WINDOW
    for p in small_odd_primes():
        first = -(start % p) * ((p + 1) // 2) % p
        survivors[first::p] = bytes(len(range(first, SEARCH_WINDOW, p)))
    return survivors


def find_prime_in_window(bits: int) -> int | None:
    start = secrets.randbits(bits) | (0b11 << (bits - 2)) | 1
    survivors = sieve_window(start)
    for index in range(SEARCH_WINDOW):
        if not survivors[index]:
            continue
        candidate = start + 2 * index
        if candidate.bit_length() != bits:
            return None
        if (candidate - 1) % PUBLIC_EXPONENT and is_probable_prime(
            candidate, FINAL_ROUNDS
        ):
            return candidate
    return None


def search_prime(bits: int) -> int:
    while True:
        prime = find_prime_in_window(bits)
        if prime is not None:
            return prime


def private_key_from_primes(p: int, q: int, e: int = PUBLIC_EXPONENT) -> PrivateKey:
    d = mod_inverse(e, (p - 1) * (q - 1))
    return PrivateKey(p * q, e, d, p, q, d % (p - 1), d % (q - 1), mod_inverse(q, p))


def generate_keypair(modulus_bits: int = MODULUS_BITS) -> PrivateKey:
    if modulus_bits < 64 or modulus_bits % 2:
        raise ValueError("modulus_bits must be even and >= 64")
    tasks = 2 * max(2, os.cpu_count() or 1)
    primes: list[int] = []
    with Pool() as pool:
        for prime in pool.imap_unordered(search_prime, [modulus_bits // 2] * tasks):
            if prime not in primes:
                primes.append(prime)
            if len(primes) == 2:
                return private_key_from_primes(*primes)
    return generate_keypair(modulus_bits)


def encrypt_int(public_key: PublicKey, m: int) -> int:
    if not 0 <= m < public_key.n:
        raise ValueError("message representative out of range")
    return mod_pow(m, public_key.e, public_key.n)


def decrypt_int(private_key: PrivateKey, c: int) -> int:
    if not 0 <= c < private_key.n:
        raise ValueError("ciphertext representative out of range")
    m1 = mod_pow(c, private_key.dp, private_key.p)
    m2 = mod_pow(c, private_key.dq, private_key.q)
    h = (m1 - m2) * private_key.q_inverse % private_key.p
    return m2 + private_key.q * h


def modulus_bytes(n: int) -> int:
    return (n.bit_length() + 7) // 8


def encrypt(public_key: PublicKey, message: bytes) -> bytes:
    k = modulus_bytes(public_key.n)
    chunk = k - PKCS1_OVERHEAD
    if chunk < 1:
        raise ValueError("modulus too short for PKCS#1 v1.5")
    blocks = [message[i : i + chunk] for i in range(0, len(message), chunk)] or [b""]
    return b"".join(_encrypt_block(public_key, k, block) for block in blocks)


def decrypt(private_key: PrivateKey, ciphertext: bytes) -> bytes:
    k = modulus_bytes(private_key.n)
    if not ciphertext or len(ciphertext) % k:
        raise ValueError("decryption error")
    blocks = [ciphertext[i : i + k] for i in range(0, len(ciphertext), k)]
    return b"".join(_decrypt_block(private_key, k, block) for block in blocks)


def _encrypt_block(public_key: PublicKey, k: int, block: bytes) -> bytes:
    padding = bytes(secrets.randbelow(255) + 1 for _ in range(k - len(block) - 3))
    encoded = b"\x00\x02" + padding + b"\x00" + block
    return encrypt_int(public_key, int.from_bytes(encoded, "big")).to_bytes(k, "big")


def _decrypt_block(private_key: PrivateKey, k: int, block: bytes) -> bytes:
    c = int.from_bytes(block, "big")
    if c >= private_key.n:
        raise ValueError("decryption error")
    encoded = decrypt_int(private_key, c).to_bytes(k, "big")
    separator = encoded.find(0, 2)
    if encoded[0] != 0 or encoded[1] != 2 or separator < 10:
        raise ValueError("decryption error")
    return encoded[separator + 1 :]


def save_private_key(private_key: PrivateKey, path: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as file:
        json.dump(
            {name: hex(value) for name, value in private_key._asdict().items()}, file
        )


def load_private_key(path: str) -> PrivateKey:
    with open(path) as file:
        return PrivateKey(
            **{name: int(value, 16) for name, value in json.load(file).items()}
        )


if __name__ == "__main__":
    started = time.perf_counter()
    key = generate_keypair(int(sys.argv[2]) if len(sys.argv) > 2 else MODULUS_BITS)
    save_private_key(key, sys.argv[1])
    print(
        f"{key.n.bit_length()}-bit key saved to {sys.argv[1]} in {time.perf_counter() - started:.1f} s"
    )
