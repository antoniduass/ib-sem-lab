import pytest

from gostcrypto.kdf import hmac_streebog512, pbkdf2_streebog512
from gostcrypto.streebog import streebog512

h = bytes.fromhex

# RFC 7836, Appendix B, example 2
HMAC_KEY = h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
HMAC_DATA = h("0126bdb87800af214341456563780100")
HMAC_VALUE = h(
    "a59bab22ecae19c65fbde6e5f4e9f5d8549d31f037f9df9b905500e171923a77"
    "3d5f1530f2ed7e964cb2eedc29e9ad2f3afe93b2814f79f5000ffc0366c251e6"
)

# RFC 9337, Appendix A
PBKDF2_VECTORS = [
    (
        b"password",
        b"salt",
        1,
        64,
        h(
            "64770af7f748c3b1c9ac831dbcfd85c26111b30a8a657ddc3056b80ca73e040d"
            "2854fd36811f6d825cc4ab66ec0a68a490a9e5cf5156b3a2b7eecddbf9a16b47"
        ),
    ),
    (
        b"password",
        b"salt",
        2,
        64,
        h(
            "5a585bafdfbb6e8830d6d68aa3b43ac00d2e4aebce01c9b31c2caed56f0236d4"
            "d34b2b8fbd2c4e89d54d46f50e47d45bbac301571743119e8d3c42ba66d348de"
        ),
    ),
    (
        b"password",
        b"salt",
        4096,
        64,
        h(
            "e52deb9a2d2aaff4e2ac9d47a41f34c20376591c67807f0477e32549dc341bc7"
            "867c09841b6d58e29d0347c996301d55df0d34e47cf68f4e3c2cdaf1d9ab86c3"
        ),
    ),
    (
        b"password",
        b"salt",
        16777216,
        64,
        h(
            "49e4843bba76e300afe24c4d23dc7392def12f2c0e244172367cd70a8982ac36"
            "1adb601c7e2a314e8cb7b1e9df840e36ab5615be5d742b6cf203fb55fdc48071"
        ),
    ),
    (
        b"passwordPASSWORDpassword",
        b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
        4096,
        100,
        h(
            "b2d8f1245fc4d29274802057e4b54e0a0753aa22fc53760b301cf008679e58fe"
            "4bee9addcae99ba2b0b20f431a9c5e50f395c89387d0945aedeca6eb4015dfc2"
            "bd2421ee9bb71183ba882ceebfef259f33f9e27dc6178cb89dc37428cf9cc52a"
            "2baa2d3a"
        ),
    ),
    (
        b"pass\x00word",
        b"sa\x00lt",
        4096,
        64,
        h(
            "50df062885b69801a3c10248eb0a27ab6e522ffeb20c991c660f001475d73a4e"
            "167f782c18e97e92976d9c1d970831ea78ccb879f67068cdac1910740844e830"
        ),
    ),
]

FAST_VECTORS = [vector for vector in PBKDF2_VECTORS if vector[2] < 10**6]


def test_hmac_matches_rfc7836():
    assert hmac_streebog512(HMAC_KEY, HMAC_DATA) == HMAC_VALUE


def test_hmac_hashes_keys_longer_than_block():
    long_key = bytes(range(100))
    assert hmac_streebog512(long_key, b"data") == hmac_streebog512(
        streebog512(long_key), b"data"
    )


def test_hmac_key_of_exactly_block_size_is_not_hashed():
    key = bytes(range(64))
    assert hmac_streebog512(key, b"data") != hmac_streebog512(streebog512(key), b"data")


@pytest.mark.parametrize(
    ("password", "salt", "iterations", "length", "expected"), FAST_VECTORS
)
def test_pbkdf2_matches_rfc9337(password, salt, iterations, length, expected):
    assert pbkdf2_streebog512(password, salt, iterations, length) == expected


def test_slow_rfc9337_vector_is_the_only_one_skipped():
    assert [vector[2] for vector in PBKDF2_VECTORS if vector not in FAST_VECTORS] == [
        16777216
    ]


def test_pbkdf2_truncates_to_requested_length():
    full = pbkdf2_streebog512(b"password", b"salt", 2, 64)
    assert pbkdf2_streebog512(b"password", b"salt", 2, 20) == full[:20]


@pytest.mark.parametrize(("iterations", "length"), [(0, 64), (1, 0), (-1, 64)])
def test_pbkdf2_rejects_bad_parameters(iterations, length):
    with pytest.raises(ValueError):
        pbkdf2_streebog512(b"password", b"salt", iterations, length)
