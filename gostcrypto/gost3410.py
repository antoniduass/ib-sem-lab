"""GOST 34.10-2018 digital signature on an elliptic curve, sections 5-6.

A point is a tuple (x, y); None is the zero point O.
"""

import secrets
from typing import NamedTuple

from gostcrypto.modular import mod_inverse
from gostcrypto.streebog import streebog512

Point = tuple[int, int] | None
Signature = tuple[int, int]


class Curve(NamedTuple):
    p: int
    a: int
    b: int
    m: int
    q: int
    x: int
    y: int

    @property
    def base_point(self) -> Point:
        return (self.x, self.y)


# RFC 7836, Appendix A.1: id-tc26-gost-3410-12-512-paramSetA
PARAMSET_512_A = Curve(
    p=int(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7",
        16,
    ),
    a=int(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc4",
        16,
    ),
    b=int(
        "e8c2505dedfc86ddc1bd0b2b6667f1da34b82574761cb0e879bd081cfd0b6265"
        "ee3cb090f30d27614cb4574010da90dd862ef9d4ebee4761503190785a71c760",
        16,
    ),
    m=int(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "27e69532f48d89116ff22b8d4e0560609b4b38abfad2b85dcacdb1411f10b275",
        16,
    ),
    q=int(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "27e69532f48d89116ff22b8d4e0560609b4b38abfad2b85dcacdb1411f10b275",
        16,
    ),
    x=3,
    y=int(
        "7503cfe87a836ae3a61b8816e25450e6ce5e1c93acf1abc1778064fdcbefa921"
        "df1626be4fd036e93d75e6a50e3a41e98028fe5fc235f5b889a589cb5215f2a4",
        16,
    ),
)


def is_on_curve(curve: Curve, point: Point) -> bool:
    if point is None:
        return True
    x, y = point
    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0


def add_points(curve: Curve, first: Point, second: Point) -> Point:
    if first is None:
        return second
    if second is None:
        return first
    p = curve.p
    x1, y1 = first
    x2, y2 = second
    if x1 != x2:
        slope = (y2 - y1) * mod_inverse(x2 - x1, p) % p
    elif y1 == y2 and y1 != 0:
        slope = (3 * x1 * x1 + curve.a) * mod_inverse(2 * y1, p) % p
    else:
        return None
    x3 = (slope * slope - x1 - x2) % p
    y3 = (slope * (x1 - x3) - y1) % p
    return (x3, y3)


def multiply_point(curve: Curve, k: int, point: Point) -> Point:
    if k < 0:
        raise ValueError("k must be >= 0")
    result = None
    for bit in bin(k)[2:]:
        result = add_points(curve, result, result)
        if bit == "1":
            result = add_points(curve, result, point)
    return result


def generate_keys(curve: Curve) -> tuple[int, Point]:
    signing_key = secrets.randbelow(curve.q - 1) + 1
    return signing_key, multiply_point(curve, signing_key, curve.base_point)


def digest_to_e(digest: bytes, q: int) -> int:
    alpha = int.from_bytes(digest, "little")
    return alpha % q or 1


def sign_with_k(curve: Curve, signing_key: int, e: int, k: int) -> Signature | None:
    point_c = multiply_point(curve, k, curve.base_point)
    r = point_c[0] % curve.q
    s = (r * signing_key + k * e) % curve.q
    if r == 0 or s == 0:
        return None
    return r, s


def verify_e(
    curve: Curve, verification_key: Point, e: int, signature: Signature
) -> bool:
    r, s = signature
    q = curve.q
    if not (0 < r < q and 0 < s < q):
        return False
    v = mod_inverse(e, q)
    z1 = s * v % q
    z2 = -r * v % q
    point_c = add_points(
        curve,
        multiply_point(curve, z1, curve.base_point),
        multiply_point(curve, z2, verification_key),
    )
    return point_c is not None and point_c[0] % q == r


def sign(curve: Curve, signing_key: int, message: bytes) -> Signature:
    e = _message_to_e(curve, message)
    while True:
        k = secrets.randbelow(curve.q - 1) + 1
        signature = sign_with_k(curve, signing_key, e, k)
        if signature is not None:
            return signature


def verify(
    curve: Curve, verification_key: Point, message: bytes, signature: Signature
) -> bool:
    return verify_e(curve, verification_key, _message_to_e(curve, message), signature)


def _message_to_e(curve: Curve, message: bytes) -> int:
    if curve.q <= 2**508:
        raise ValueError(
            "only 512-bit curves are supported: Streebog-256 is not implemented"
        )
    return digest_to_e(streebog512(message), curve.q)
