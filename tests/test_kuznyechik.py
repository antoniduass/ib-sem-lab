import pytest

from gostcrypto.kuznyechik import (
    ROUND_CONSTANTS,
    decrypt_block,
    encrypt_block,
    f_transform,
    l_inverse,
    l_transform,
    lsx,
    r_inverse,
    r_transform,
    round_keys,
    s_inverse,
    s_transform,
    x_transform,
)

h = bytes.fromhex

# GOST 34.12-2018, A.2.1 (PDF p. 12, printed p. 7)
S_PAIRS = [
    ("ffeeddccbbaa99881122334455667700", "b66cd8887d38e8d77765aeea0c9a7efc"),
    ("b66cd8887d38e8d77765aeea0c9a7efc", "559d8dd7bd06cbfe7e7b262523280d39"),
    ("559d8dd7bd06cbfe7e7b262523280d39", "0c3322fed531e4630d80ef5c5a81c50b"),
    ("0c3322fed531e4630d80ef5c5a81c50b", "23ae65633f842d29c5df529c13f5acda"),
]

# GOST 34.12-2018, A.2.2 (PDF p. 12, printed p. 7).
# Pair 3 is printed as R(0594...) = 640594..., which contradicts formula (5)
# (it gives 290594...). The examples form a chain: pair 2 outputs a594...,
# and 64a594... is the input of pair 4 and of A.2.3 L #1, so the symbol "a"
# was lost in print. Corrected value approved by the user (defect D1).
R_PAIRS = [
    ("00000000000000000000000000000100", "94000000000000000000000000000001"),
    ("94000000000000000000000000000001", "a5940000000000000000000000000000"),
    ("a5940000000000000000000000000000", "64a59400000000000000000000000000"),
    ("64a59400000000000000000000000000", "0d64a594000000000000000000000000"),
]

# GOST 34.12-2018, A.2.3 (PDF p. 12, printed p. 7)
L_PAIRS = [
    ("64a59400000000000000000000000000", "d456584dd0e3e84cc3166e4b7fa2890d"),
    ("d456584dd0e3e84cc3166e4b7fa2890d", "79d26221b87b584cd42fbc4ffea5de9a"),
    ("79d26221b87b584cd42fbc4ffea5de9a", "0e93691a0cfc60408b7b68f66b513c13"),
    ("0e93691a0cfc60408b7b68f66b513c13", "e6a8094fee0aa204fd97bcb0b44b8580"),
]

# GOST 34.12-2018, A.2.4 (PDF p. 12-13, printed p. 7-8)
KEY = h("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
C1_TO_C8 = [
    "6ea276726c487ab85d27bd10dd849401",
    "dc87ece4d890f4b3ba4eb92079cbeb02",
    "b2259a96b4d88e0be7690430a44f7f03",
    "7bcd1b0b73e32ba5b79cb140f2551504",
    "156f6d791fab511deabb0c502fd18105",
    "a74af7efab73df160dd208608b9efe06",
    "c9e8819dc73ba5ae50f5b570561a6a07",
    "f6593616e6055689adfba18027aa2a08",
]
X_C1_K1 = "e63bdcc9a09594475d369f2399d1f276"
SX_C1_K1 = "0998ca37a7947aabb78f4a5ae81b748a"
LSX_C1_K1 = "3d0940999db75d6a9257071d5e6144a6"
F_STEPS = [
    ("c3d5fa01ebe36f7a9374427ad7ca8949", "8899aabbccddeeff0011223344556677"),
    ("37777748e56453377d5e262d90903f87", "c3d5fa01ebe36f7a9374427ad7ca8949"),
    ("f9eae5f29b2815e31f11ac5d9c29fb01", "37777748e56453377d5e262d90903f87"),
    ("e980089683d00d4be37dd3434699b98f", "f9eae5f29b2815e31f11ac5d9c29fb01"),
    ("b7bd70acea4460714f4ebe13835cf004", "e980089683d00d4be37dd3434699b98f"),
    ("1a46ea1cf6ccd236467287df93fdf974", "b7bd70acea4460714f4ebe13835cf004"),
    ("3d4553d8e9cfec6815ebadc40a9ffd04", "1a46ea1cf6ccd236467287df93fdf974"),
    ("db31485315694343228d6aef8cc78c44", "3d4553d8e9cfec6815ebadc40a9ffd04"),
]
K1_TO_K10 = [
    "8899aabbccddeeff0011223344556677",
    "fedcba98765432100123456789abcdef",
    "db31485315694343228d6aef8cc78c44",
    "3d4553d8e9cfec6815ebadc40a9ffd04",
    "57646468c44a5e28d3e59246f429f1ac",
    "bd079435165c6432b532e82834da581b",
    "51e640757e8745de705727265a0098b1",
    "5a7925017b9fdd3ed72a91a22286f984",
    "bb44e25378c73123a5f32f73cdb6e517",
    "72e9dd7416bcf45b755dbaa88e4a4043",
]

# GOST 34.12-2018, A.2.5 (PDF p. 13-14, printed p. 8-9)
PLAINTEXT = "1122334455667700ffeeddccbbaa9988"
CIPHERTEXT = "7f679d90bebc24305a468d42b9d4edcd"
X_K1_A = "99bb99ff99bb99ffffffffffffffffff"
SX_K1_A = "e87de8b6e87de8b6b6b6b6b6b6b6b6b6"
LSX_AFTER_ROUND = [
    "e297b686e355b0a1cf4a2f9249140830",
    "285e497a0862d596b36f4258a1c69072",
    "0187a3a429b567841ad50d29207cc34e",
    "ec9bdba057d4f4d77c5d70619dcad206",
    "1357fd11de9257290c2a1473eb6bcde1",
    "28ae31e7d4c2354261027ef0b32897df",
    "07e223d56002c013d3f5e6f714b86d2d",
    "cd8ef6cd97e0e092a8e4cca61b38bf65",
    "0d8e40e4a800d06b2f1b37ea379ead8e",
]

# GOST 34.12-2018, A.2.6 (PDF p. 14, printed p. 9)
X_K10_B = "0d8e40e4a800d06b2f1b37ea379ead8e"
L_INV_X_K10_B = "8a6b930a52211b45c5baa43ff8b91319"
S_INV_L_INV_X_K10_TO_K2 = [
    "76ca149eef27d1b10d17e3d5d68e5a72",
    "5d9b06d41b9d1d2d04df7755363e94a9",
    "79487192aa45709c115559d6e9280f6e",
    "ae506924c8ce331bb918fc5bdfb195fa",
    "bbffbfc8939eaaffafb8e22769e323aa",
    "3cc2f07cc07a8bec0f3ea0ed2ae33e4a",
    "f36f01291d0b96d591e228b72d011c36",
    "1c4b0c1e950182b1ce696af5c0bfc5df",
    "99bb99ff99bb99ffffffffffffffffff",
]


@pytest.mark.parametrize(("a", "expected"), S_PAIRS)
def test_s_transform(a, expected):
    assert s_transform(h(a)) == h(expected)
    assert s_inverse(h(expected)) == h(a)


@pytest.mark.parametrize(("a", "expected"), R_PAIRS)
def test_r_transform(a, expected):
    assert r_transform(h(a)) == h(expected)
    assert r_inverse(h(expected)) == h(a)


@pytest.mark.parametrize(("a", "expected"), L_PAIRS)
def test_l_transform(a, expected):
    assert l_transform(h(a)) == h(expected)
    assert l_inverse(h(expected)) == h(a)


def test_round_constants():
    assert ROUND_CONSTANTS[:8] == tuple(h(c) for c in C1_TO_C8)


def test_first_key_schedule_round():
    k1 = KEY[:16]
    c1 = h(C1_TO_C8[0])
    assert x_transform(c1, k1) == h(X_C1_K1)
    assert s_transform(h(X_C1_K1)) == h(SX_C1_K1)
    assert lsx(c1, k1) == h(LSX_C1_K1)


def test_key_schedule_f_steps():
    a1, a0 = KEY[:16], KEY[16:]
    for constant, (expected_a1, expected_a0) in zip(C1_TO_C8, F_STEPS, strict=True):
        a1, a0 = f_transform(h(constant), a1, a0)
        assert (a1, a0) == (h(expected_a1), h(expected_a0))


def test_round_keys():
    assert round_keys(KEY) == [h(k) for k in K1_TO_K10]


def test_encryption_rounds():
    keys = [h(k) for k in K1_TO_K10]
    a = h(PLAINTEXT)
    assert x_transform(keys[0], a) == h(X_K1_A)
    assert s_transform(h(X_K1_A)) == h(SX_K1_A)
    for key, expected in zip(keys[:9], LSX_AFTER_ROUND, strict=True):
        a = lsx(key, a)
        assert a == h(expected)
    assert x_transform(keys[9], a) == h(CIPHERTEXT)


def test_encrypt_block():
    assert encrypt_block(KEY, h(PLAINTEXT)) == h(CIPHERTEXT)


def test_decryption_rounds():
    keys = [h(k) for k in K1_TO_K10]
    b = h(CIPHERTEXT)
    assert x_transform(keys[9], b) == h(X_K10_B)
    assert l_inverse(h(X_K10_B)) == h(L_INV_X_K10_B)
    for key, expected in zip(keys[9:0:-1], S_INV_L_INV_X_K10_TO_K2, strict=True):
        b = s_inverse(l_inverse(x_transform(key, b)))
        assert b == h(expected)
    assert x_transform(keys[0], b) == h(PLAINTEXT)


def test_decrypt_block():
    assert decrypt_block(KEY, h(CIPHERTEXT)) == h(PLAINTEXT)


@pytest.mark.parametrize(
    "block",
    [bytes(16), b"\xff" * 16, bytes(range(16)), h(CIPHERTEXT), b"0123456789abcdef"],
)
def test_encrypt_decrypt_round_trip(block):
    ciphertext = encrypt_block(KEY, block)
    assert ciphertext != block
    assert decrypt_block(KEY, ciphertext) == block


@pytest.mark.parametrize("length", [0, 15, 17, 32])
def test_wrong_block_length(length):
    with pytest.raises(ValueError):
        encrypt_block(KEY, bytes(length))
    with pytest.raises(ValueError):
        decrypt_block(KEY, bytes(length))


@pytest.mark.parametrize("length", [0, 16, 31, 33])
def test_wrong_key_length(length):
    with pytest.raises(ValueError):
        encrypt_block(bytes(length), bytes(16))
    with pytest.raises(ValueError):
        decrypt_block(bytes(length), bytes(16))
