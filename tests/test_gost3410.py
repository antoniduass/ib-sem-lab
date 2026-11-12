import pytest

from gostcrypto.gost3410 import (
    PARAMSET_512_A,
    Curve,
    add_points,
    digest_to_e,
    generate_keys,
    is_on_curve,
    multiply_point,
    sign,
    sign_with_k,
    verify,
    verify_e,
)
from gostcrypto.modular import mod_inverse
from gostcrypto.primes import is_probable_prime

# GOST 34.10-2018, A.2: A.2.1.2-A.2.1.6, A.2.1.7-A.2.1.8
A2 = {
    "curve": Curve(
        p=0x8000000000000000000000000000000000000000000000000000000000000431,
        a=0x7,
        b=0x5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E,
        m=0x8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3,
        q=0x8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3,
        x=0x2,
        y=0x8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8,
    ),
    "d": 0x7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28,
    "qx": 0x7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B,
    "qy": 0x26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA,
    "e": 0x2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5,
    "k": 0x77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3,
    "cx": 0x41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493,
    "cy": 0x489C375A9941A3049E33B34361DD204172AD98C3E5916DE27695D22A61FAE46E,
    "r": 0x41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493,
    "s": 0x1456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40,
    "v": 0x271A4EE429F84EBC423E388964555BB29D3BA53C7BF945E5FAC8F381706354C2,
    "z1": 0x5358F8FFB38F7C09ABC782A2DF2A3927DA4077D07205F763682F3A76C9019B4F,
    "z2": 0x3221B4FBBF6D101074EC14AFAC2D4F7EFAC4CF9FEC1ED11BAE336D27D527665,
    "vcx": 0x41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493,
    "vcy": 0x489C375A9941A3049E33B34361DD204172AD98C3E5916DE27695D22A61FAE46E,
    "big_r": 0x41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493,
}

# GOST 34.10-2018, A.3: A.3.1.2-A.3.1.6, A.3.1.7-A.3.1.8
A3 = {
    "curve": Curve(
        p=int(
            "4531acd1fe0023c7550d267b6b2fee80922b14b2ffb90f04d4eb7c09b5d2d15d"
            "f1d852741af4704a0458047e80e4546d35b8336fac224dd81664bbf528be6373",
            16,
        ),
        a=0x7,
        b=int(
            "1cff0806a31116da29d8cfa54e57eb748bc5f377e49400fdd788b649eca1ac43"
            "61834013b2ad7322480a89ca58e0cf74bc9e540c2add6897fad0a3084f302adc",
            16,
        ),
        m=int(
            "4531acd1fe0023c7550d267b6b2fee80922b14b2ffb90f04d4eb7c09b5d2d15d"
            "a82f2d7ecb1dbac719905c5eecc423f1d86e25edbe23c595d644aaf187e6e6df",
            16,
        ),
        q=int(
            "4531acd1fe0023c7550d267b6b2fee80922b14b2ffb90f04d4eb7c09b5d2d15d"
            "a82f2d7ecb1dbac719905c5eecc423f1d86e25edbe23c595d644aaf187e6e6df",
            16,
        ),
        x=int(
            "24d19cc64572ee30f396bf6ebbfd7a6c5213b3b3d7057cc825f91093a68cd762"
            "fd60611262cd838dc6b60aa7eee804e28bc849977fac33b4b530f1b120248a9a",
            16,
        ),
        y=int(
            "2bb312a43bd2ce6e0d020613c857acddcfbf061e91e5f2c3f32447c259f39b2c"
            "83ab156d77f1496bf7eb3351e1ee4e43dc1a18b91b24640b6dbb92cb1add371e",
            16,
        ),
    ),
    "d": int(
        "ba6048aadae241ba40936d47756d7c93091a0e8514669700ee7508e508b1020"
        "72e8123b2200a0563322dad2827e2714a2636b7bfd18aadfc62967821fa18dd4",
        16,
    ),
    "qx": int(
        "115dc5bc96760c7b48598d8ab9e740d4c4a85a65be33c1815b5c320c854621dd"
        "5a515856d13314af69bc5b924c8b4ddff75c45415c1d9dd9dd33612cd530efe1",
        16,
    ),
    "qy": int(
        "37c7c90cd40b0f5621dc3ac1b751cfa0e2634fa0503b3d52639f5d7fb72afd61"
        "ea199441d943ffe7f0c70a2759a3cdb84c114e1f9339fdf27f35eca93677beec",
        16,
    ),
    "e": int(
        "3754f3cfacc9e0615c4f4a7c4d8dab531b09b6f9c170c533a71d147035b0c591"
        "7184ee536593f4414339976c647c5d5a407adedb1d560c4fc6777d2972075b8c",
        16,
    ),
    "k": int(
        "359e7f4b1410feacc570456c6801496946312120b39d019d455986e364f3658"
        "86748ed7a44b3e794434006011842286212273a6d14cf70ea3af71bb1ae679f1",
        16,
    ),
    "cx": int(
        "2f86fa60a081091a23dd795e1e3c689ee512a3c82ee0dcc2643c78eea8fcacd3"
        "5492558486b20f1c9ec197c90699850260c93bcbcd9c5c3317e19344e173ae36",
        16,
    ),
    "cy": int(
        "eb488140f7e2f4e35cf220bdbc75ae44f26f9c7df52e82436bde80a91831da2"
        "7c8100daa876f9adc0d28a82dd3826d4dc7f92e471da23e55e0ebb3927c85bd6",
        16,
    ),
    "r": int(
        "2f86fa60a081091a23dd795e1e3c689ee512a3c82ee0dcc2643c78eea8fcacd3"
        "5492558486b20f1c9ec197c90699850260c93bcbcd9c5c3317e19344e173ae36",
        16,
    ),
    "s": int(
        "1081b394696ffe8e6585e7a9362d26b6325f56778aadbc081c0bfbe933d52ff5"
        "823ce288e8c4f362526080df7f70ce406a6eeb1f56919cb92a9853bde73e5b4a",
        16,
    ),
    "v": int(
        "30d212a9e25d1a80a0f238532cadf3e64d7ef4e782b6ad140aaf8bbd9bb47298"
        "4595eec87b2f3448a1999d5f0a6de0e14a55ad875721ec8cfd504000b3a840ff",
        16,
    ),
    "z1": int(
        "3d38e7262d69bb2ad24dd81eea2f92e6348d619fa45007b175837cf13b026079"
        "051a48a1a379188f37ba46ce12f7207f2a8345459ff960e1ebd5b4f2a34a6eef",
        16,
    ),
    "z2": int(
        "1a18a31602e6eac0a9888c01941082aefe296f840453d2603414c2a16eb6fc52"
        "9d8d8372e50dc49d6c612ce1ff65bd58e1d2029f22690438cc36a76dda444acb",
        16,
    ),
    "vcx": int(
        "2f86fa60a081091a23dd795e1e3c689ee512a3c82ee0dcc2643c78eea8fcacd3"
        "5492558486b20f1c9ec197c90699850260c93bcbcd9c5c3317e19344e173ae36",
        16,
    ),
    "vcy": int(
        "eb488140f7e2f4e35cf220bdbc75ae44f26f9c7df52e82436bde80a91831da2"
        "7c8100daa876f9adc0d28a82dd3826d4dc7f92e471da23e55e0ebb3927c85bd6",
        16,
    ),
    "big_r": int(
        "2f86fa60a081091a23dd795e1e3c689ee512a3c82ee0dcc2643c78eea8fcacd3"
        "5492558486b20f1c9ec197c90699850260c93bcbcd9c5c3317e19344e173ae36",
        16,
    ),
}

EXAMPLES = [A2, A3]
EXAMPLE_IDS = ["A.2", "A.3"]
ALL_CURVES = [A2["curve"], A3["curve"], PARAMSET_512_A]
CURVE_IDS = ["A.2", "A.3", "paramSetA"]

# RFC 7836, Appendix B, examples 7-8 (keys are little-endian octet strings)
RFC7836_KEY_PAIRS = [
    (
        (
            "c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8"
            "c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667"
        ),
        (
            "aab0eda4abff21208d18799fb9a8556654ba783070eba10cb9abb253ec56dcf5"
            "d3ccba6192e464e6e5bcb6dea137792f2431f6c897eb1b3c0cc14327b1adc0a7"
            "914613a3074e363aedb204d38d3563971bd8758e878c9db11403721b48002d38"
            "461f92472d40ea92f9958c0ffa4c93756401b97f89fdbe0b5e46e4a4631cdb5a"
        ),
    ),
    (
        (
            "48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b"
            "8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db"
        ),
        (
            "192fe183b9713a077253c72c8735de2ea42a3dbc66ea317838b65fa32523cd5e"
            "fca974eda7c863f4954d1147f1f2b25c395fce1c129175e876d132e94ed5a651"
            "04883b414c9b592ec4dc84826f07d0b6d9006dda176ce48c391e3f97d102e03b"
            "b598bf132a228a45f7201aba08fc524a2d77e43a362ab022ad4028f75bde3b79"
        ),
    ),
]


def j_invariant_is_allowed(curve):
    return curve.a % curve.p != 0 and curve.b % curve.p != 0


@pytest.mark.parametrize("curve", ALL_CURVES, ids=CURVE_IDS)
def test_curve_parameters_meet_section_5_3(curve):
    p, a, b, m, q = curve.p, curve.a, curve.b, curve.m, curve.q
    assert is_probable_prime(p) and p > 3
    assert is_probable_prime(q)
    assert 2**254 < q < 2**256 or 2**508 < q < 2**512
    assert (4 * a**3 + 27 * b**2) % p != 0
    assert m % q == 0 and m != p
    assert (m - p - 1) ** 2 <= 4 * p
    bound = 31 if q < 2**256 else 131
    assert all(pow(p, t, q) != 1 for t in range(1, bound + 1))
    assert j_invariant_is_allowed(curve)


@pytest.mark.parametrize("curve", ALL_CURVES, ids=CURVE_IDS)
def test_base_point_has_order_q(curve):
    assert is_on_curve(curve, curve.base_point)
    assert multiply_point(curve, curve.q, curve.base_point) is None
    assert multiply_point(curve, curve.q - 1, curve.base_point) == (
        curve.x,
        -curve.y % curve.p,
    )


@pytest.mark.parametrize("example", EXAMPLES, ids=EXAMPLE_IDS)
def test_verification_key_is_d_times_p(example):
    curve = example["curve"]
    assert multiply_point(curve, example["d"], curve.base_point) == (
        example["qx"],
        example["qy"],
    )


@pytest.mark.parametrize("example", EXAMPLES, ids=EXAMPLE_IDS)
def test_signing_matches_section_a_2(example):
    curve = example["curve"]
    assert multiply_point(curve, example["k"], curve.base_point) == (
        example["cx"],
        example["cy"],
    )
    signature = sign_with_k(curve, example["d"], example["e"], example["k"])
    assert signature == (example["r"], example["s"])


@pytest.mark.parametrize("example", EXAMPLES, ids=EXAMPLE_IDS)
def test_verification_intermediate_values(example):
    curve, q = example["curve"], example["curve"].q
    v = mod_inverse(example["e"], q)
    z1 = example["s"] * v % q
    z2 = -example["r"] * v % q
    point_c = add_points(
        curve,
        multiply_point(curve, z1, curve.base_point),
        multiply_point(curve, z2, (example["qx"], example["qy"])),
    )
    assert (v, z1, z2) == (example["v"], example["z1"], example["z2"])
    assert point_c == (example["vcx"], example["vcy"])
    assert point_c[0] % q == example["big_r"] == example["r"]


@pytest.mark.parametrize("example", EXAMPLES, ids=EXAMPLE_IDS)
def test_verify_accepts_gost_signature(example):
    key = (example["qx"], example["qy"])
    signature = (example["r"], example["s"])
    assert verify_e(example["curve"], key, example["e"], signature)


@pytest.mark.parametrize("example", EXAMPLES, ids=EXAMPLE_IDS)
def test_verify_rejects_tampering(example):
    curve, q = example["curve"], example["curve"].q
    key = (example["qx"], example["qy"])
    r, s, e = example["r"], example["s"], example["e"]
    other_key = multiply_point(curve, 2, curve.base_point)
    assert not verify_e(curve, key, e + 1, (r, s))
    assert not verify_e(curve, key, e, (r + 1, s))
    assert not verify_e(curve, key, e, (r, s + 1))
    assert not verify_e(curve, other_key, e, (r, s))
    for bad in [(0, s), (r, 0), (q, s), (r, q), (-r, s), (r, s + q)]:
        assert not verify_e(curve, key, e, bad)


def test_digest_to_e_reads_little_endian_and_replaces_zero():
    q = A3["curve"].q
    assert digest_to_e(b"\x01" + bytes(63), q) == 1
    assert digest_to_e(bytes(63) + b"\x01", q) == 2**504
    assert digest_to_e(bytes(64), q) == 1
    assert digest_to_e(q.to_bytes(64, "little"), q) == 1
    assert digest_to_e((q + 5).to_bytes(64, "little"), q) == 5


@pytest.mark.parametrize(("private", "public"), RFC7836_KEY_PAIRS)
def test_rfc7836_paramset_a_key_pairs(private, public):
    private_bytes = bytes.fromhex(private)
    public_bytes = bytes.fromhex(public)
    d = int.from_bytes(private_bytes, "little")
    expected = (
        int.from_bytes(public_bytes[:64], "little"),
        int.from_bytes(public_bytes[64:], "little"),
    )
    assert multiply_point(PARAMSET_512_A, d, PARAMSET_512_A.base_point) == expected


def test_point_addition_cases():
    curve = A2["curve"]
    point = curve.base_point
    negative = (curve.x, -curve.y % curve.p)
    doubled = add_points(curve, point, point)
    assert add_points(curve, None, point) == point
    assert add_points(curve, point, None) == point
    assert add_points(curve, point, negative) is None
    assert is_on_curve(curve, doubled)
    assert add_points(curve, doubled, point) == multiply_point(curve, 3, point)
    assert multiply_point(curve, 0, point) is None
    assert multiply_point(curve, 1, point) == point
    with pytest.raises(ValueError):
        multiply_point(curve, -1, point)


def test_generated_keys_are_valid():
    d, key = generate_keys(PARAMSET_512_A)
    assert 0 < d < PARAMSET_512_A.q
    assert is_on_curve(PARAMSET_512_A, key)
    assert key == multiply_point(PARAMSET_512_A, d, PARAMSET_512_A.base_point)


def test_sign_and_verify_message_on_working_curve():
    d, key = generate_keys(PARAMSET_512_A)
    message = "Защищённый блокнот".encode()
    signature = sign(PARAMSET_512_A, d, message)
    assert verify(PARAMSET_512_A, key, message, signature)
    assert not verify(PARAMSET_512_A, key, message + b"!", signature)
    assert sign(PARAMSET_512_A, d, message) != signature


def test_message_signing_requires_512_bit_curve():
    with pytest.raises(ValueError):
        sign(A2["curve"], A2["d"], b"message")
    with pytest.raises(ValueError):
        verify(A2["curve"], (A2["qx"], A2["qy"]), b"message", (A2["r"], A2["s"]))
