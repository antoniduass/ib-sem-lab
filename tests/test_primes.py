import pytest

from gostcrypto.primes import is_probable_prime, is_strong_probable_prime

# GOST 34.10-2018, A.2.1 (PDF p. 14) and A.3.1 (PDF pp. 16-17): p and q
GOST_PRIMES = [
    0x8000000000000000000000000000000000000000000000000000000000000431,
    0x8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3,
    int(
        "4531acd1fe0023c7550d267b6b2fee80922b14b2ffb90f04d4eb7c09b5d2d15d"
        "f1d852741af4704a0458047e80e4546d35b8336fac224dd81664bbf528be6373",
        16,
    ),
    int(
        "4531acd1fe0023c7550d267b6b2fee80922b14b2ffb90f04d4eb7c09b5d2d15d"
        "a82f2d7ecb1dbac719905c5eecc423f1d86e25edbe23c595d644aaf187e6e6df",
        16,
    ),
]

MERSENNE_PRIMES = [2**127 - 1, 2**521 - 1, 2**607 - 1]

SMALL_CARMICHAEL = [561, 1105, 1729, 2465, 2821, 6601, 8911]

# Chernick form (6k+1)(12k+1)(18k+1), k = 195: no factor below 1000
LARGE_CARMICHAEL = 1171 * 2341 * 3511

# Cole, 1903
MERSENNE_COMPOSITE = 2**67 - 1


def is_prime_by_trial_division(n):
    return n >= 2 and all(n % d for d in range(2, int(n**0.5) + 1))


def test_gost_primes_have_expected_lengths():
    assert [p.bit_length() for p in GOST_PRIMES] == [256, 256, 511, 511]


@pytest.mark.parametrize("n", GOST_PRIMES + MERSENNE_PRIMES)
def test_known_large_primes(n):
    assert is_probable_prime(n)


def test_matches_trial_division_below_10000():
    for n in range(-5, 10000):
        assert is_probable_prime(n) == is_prime_by_trial_division(n), n


@pytest.mark.parametrize("n", SMALL_CARMICHAEL + [LARGE_CARMICHAEL])
def test_carmichael_numbers_fool_fermat_but_not_miller_rabin(n):
    assert pow(2, n - 1, n) == 1
    assert not is_probable_prime(n)


def test_large_carmichael_has_no_small_factor():
    factors = [1171, 2341, 3511]
    assert all(map(is_prime_by_trial_division, factors))
    assert all((LARGE_CARMICHAEL - 1) % (f - 1) == 0 for f in factors)
    assert min(factors) > 1000


def test_mersenne_composite():
    assert MERSENNE_COMPOSITE == 193707721 * 761838257287
    assert not is_probable_prime(MERSENNE_COMPOSITE)


def test_products_of_large_primes_are_composite():
    p256, q256, p512, q512 = GOST_PRIMES
    assert not is_probable_prime(p256 * q256)
    assert not is_probable_prime(p512 * q512)
    assert not is_probable_prime(MERSENNE_PRIMES[0] ** 2)


def test_2047_is_strong_pseudoprime_to_base_2_only():
    assert 2047 == 23 * 89
    assert is_strong_probable_prime(2047, 2)
    assert not is_strong_probable_prime(2047, 3)


@pytest.mark.parametrize("base", [2, 3, 5, 7, 2**100])
def test_prime_passes_every_base(base):
    assert is_strong_probable_prime(MERSENNE_PRIMES[0], base)
