import secrets

import pytest

from gostcrypto.modular import mod_inverse, mod_pow

# Textbook RSA: p = 61, q = 53, e = 17 -> n = 3233, phi = 3120, d = 2753; 65 -> 2790
TEXTBOOK_N = 3233
TEXTBOOK_PHI = 3120
TEXTBOOK_E = 17
TEXTBOOK_D = 2753


def test_textbook_rsa_key():
    assert TEXTBOOK_N == 61 * 53
    assert TEXTBOOK_PHI == 60 * 52
    assert mod_inverse(TEXTBOOK_E, TEXTBOOK_PHI) == TEXTBOOK_D


def test_textbook_rsa_round():
    assert mod_pow(65, TEXTBOOK_E, TEXTBOOK_N) == 2790
    assert mod_pow(2790, TEXTBOOK_D, TEXTBOOK_N) == 65


@pytest.mark.parametrize(
    ("base", "exponent", "modulus", "expected"),
    [
        (4, 13, 497, 445),
        (2, 10, 1000, 24),
        (3, 0, 7, 1),
        (0, 0, 7, 1),
        (0, 5, 7, 0),
        (5, 3, 1, 0),
        (5, 0, 1, 0),
        (-2, 3, 7, 6),
        (10, 1, 7, 3),
    ],
)
def test_mod_pow_small_values(base, exponent, modulus, expected):
    assert mod_pow(base, exponent, modulus) == expected


@pytest.mark.parametrize("bits", [64, 512, 2048])
def test_mod_pow_matches_builtin(bits):
    for _ in range(5):
        modulus = secrets.randbits(bits) | 1
        base = secrets.randbits(bits + 8)
        exponent = secrets.randbits(bits)
        assert mod_pow(base, exponent, modulus) == pow(base, exponent, modulus)


@pytest.mark.parametrize(("exponent", "modulus"), [(-1, 7), (3, 0), (3, -7)])
def test_mod_pow_rejects_invalid_arguments(exponent, modulus):
    with pytest.raises(ValueError):
        mod_pow(2, exponent, modulus)


@pytest.mark.parametrize(
    ("value", "modulus", "expected"),
    [(3, 7, 5), (10, 17, 12), (-3, 7, 2), (1, 2, 1), (8, 1, 0)],
)
def test_mod_inverse_small_values(value, modulus, expected):
    assert mod_inverse(value, modulus) == expected


@pytest.mark.parametrize("bits", [64, 512, 2048])
def test_mod_inverse_matches_builtin(bits):
    for _ in range(5):
        modulus = secrets.randbits(bits) | 1
        value = secrets.randbits(bits + 8)
        try:
            expected = pow(value, -1, modulus)
        except ValueError:
            continue
        inverse = mod_inverse(value, modulus)
        assert inverse == expected
        assert value * inverse % modulus == 1


@pytest.mark.parametrize(("value", "modulus"), [(6, 9), (0, 7), (14, 21), (3, 0)])
def test_mod_inverse_rejects_non_invertible(value, modulus):
    with pytest.raises(ValueError):
        mod_inverse(value, modulus)
