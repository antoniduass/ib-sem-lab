import pytest

from gostcrypto.streebog import (
    compress,
    l_transform,
    lps,
    p_transform,
    round_keys,
    s_transform,
    streebog512,
)


def vector(gost_hex: str) -> int:
    return int(gost_hex, 16)


def message_bytes(gost_hex: str) -> bytes:
    return bytes.fromhex(gost_hex)[::-1]


# GOST 34.11-2018, A.2 (PDF p. 11-13, printed p. 7-9)
M1 = (
    "32313039383736353433323130393837363534333231303938373635343332"
    "3130393837363534333231303938373635343332313039383736353433323130"
)
H1 = (
    "486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00"
    "fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b"
)
M1_PADDED = "01" + M1
K_FROM_ZERO = "b383fc2eced4a574" * 8
X_K1_M = (
    "b2b1cd1ef7ec924286b7cf1cffe49c4c84b5c91afde694448abbcb18fbe09646"
    "82b3c516f9e2904080b1cd1ef7ec924286b7cf1cffe49c4c84b5c91afde69444"
)
SX_K1_M = (
    "4645d95fc0beec2c432f8914b62d4efd3e5e37f14b097aead67de417c220b048"
    "2492ac996667e0ebdf45d95fc0beec2c432f8914b62d4efd3e5e37f14b097aea"
)
PSX_K1_M = (
    "46433ed624df433e452f5e7d92452f5ed98937e4acd989375f14f117995f14f1"
    "c0b64bc266c0b64bbe2d092067be2d09ec4e7ab0e0ec4e7a2cfdea48eb2cfdea"
)
LPSX_K1_M = (
    "e60059d4d8e0758024c73f6f3183653f56579189602ae4c21e7953ebc0e212a0"
    "ce78a8df475c2fd4fc43fc4b71c01e35be465fb20dad2cf690cdf65028121bb9"
)
K1_XOR_C1 = (
    "028ba7f4d01e7f9d5848d3af0eb1d96b9ce98a6de0917562c2cd44a3bb516188"
    "f8ff1cbf5cb3cc7511c1d6266ab47661b6f5881802a0e8576e0399773c72e073"
)
S_K1_XOR_C1 = (
    "ddf644e6e15f5733bff249410445536f4e9bd69e200f3596b3d9ea737d70a1d7"
    "d1b6143b9c9288357758f8ef78278aa155f4d717dda7cb12b211e87e7f19203d"
)
PS_K1_XOR_C1 = (
    "ddbf4eb3d17755b2f6f29bd9b658f4114449d6ea14f8d7e8e6419e733bef177e"
    "e104207d9c78dd7f5f450f709227a719575335a1888acb20336f96d735a1123d"
)
K2 = (
    "d0b00807642fd78f13f2c3ebc774e80de0e902d23aef2ee9a73d010807dae9c1"
    "88be14f0b2da27973569cd2ba051301036f728bd1d7eec33f4d18af70c46cf1e"
)
K12 = (
    "9d46bf66234a7ed06c3b2120d2a3f15e0fedd87189b75b3cd2f206906b5ee00d"
    "c9a1eab800fb8cc5760b251f4db5cdef427052fa345613fd076451901279ee4c"
)
K13 = (
    "0f79104026b900d8d768b6e223484c9761e3c585b3a405a6d2d8565ada926c3f"
    "7782ef127cd6b98290bf612558b4b60aa3cbc28fd94f95460d76b621cb45be70"
)
H1_AFTER_G_N = (
    "fd102cf8812ccb1191ea34af21394f3817a86641445aa9a626488adb33738ebd"
    "2754f6908cbbbac5d3ed0f522c50815c954135793fb1f5d905fee4736b3bdae2"
)
H1_AFTER_G0_N = (
    "5c881fd924695cf196c2e4fec20d14b642026f2a0b1716ebaabb7067d4d59752"
    "3d2db69d6d3794622147a14f19a66e7f9037e1d662d34501a8901a5de7771d7c"
)
N1 = 504

# GOST 34.11-2018, A.3 (PDF p. 15-18, printed p. 11-14)
M2 = (
    "fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f1"
    "20faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1"
)
H2 = (
    "28fbc9bada033b1460642bdcddb90c3fb3e56c497ccd0f62b8a2ad4935e85f03"
    "7613966de4ee00531ae60f3b5a47f8dae06915d5f2f194996fcabf2622e6881e"
)
M2_FIRST_BLOCK_X_K1 = (
    "486906c521f45a8f43621cde3bf44599936b10ce2531558642a303de20388585"
    "93790ed02b3685585b750fc32cf44d925d6214de3c0585585b730ecb2cf440a5"
)
M2_FIRST_BLOCK_LPSX_K1 = (
    "909aa733e1f52321a2fe35bfb8f67e92fbc70ef544709d5739d8faaca4acf126"
    "e83e273745c25b7b8f4a83a7436f6353753cbbbe492262cd3a868eace0104af1"
)


def test_a2_hash():
    assert streebog512(message_bytes(M1)) == message_bytes(H1)


def test_a2_message_is_ascii_digits():
    assert (
        message_bytes(M1)
        == b"012345678901234567890123456789012345678901234567890123456789012"
    )


def test_a3_hash():
    assert streebog512(message_bytes(M2)) == message_bytes(H2)


def test_s_transform():
    assert s_transform(vector(X_K1_M)) == vector(SX_K1_M)
    assert s_transform(vector(K1_XOR_C1)) == vector(S_K1_XOR_C1)
    assert s_transform(0) == vector("fc" * 64)


def test_p_transform():
    assert p_transform(vector(SX_K1_M)) == vector(PSX_K1_M)
    assert p_transform(vector(S_K1_XOR_C1)) == vector(PS_K1_XOR_C1)


def test_l_transform():
    assert l_transform(vector(PSX_K1_M)) == vector(LPSX_K1_M)
    assert l_transform(vector(PS_K1_XOR_C1)) == vector(K2)
    assert l_transform(vector("fc" * 64)) == vector(K_FROM_ZERO)


def test_lps_of_first_block_of_a3():
    k = lps(0)
    m = vector(M2[-128:])
    assert k ^ m == vector(M2_FIRST_BLOCK_X_K1)
    assert lps(k ^ m) == vector(M2_FIRST_BLOCK_LPSX_K1)


def test_round_keys_of_a2():
    keys = round_keys(vector(K_FROM_ZERO))
    assert len(keys) == 13
    assert keys[1] == vector(K2)
    assert keys[11] == vector(K12)
    assert keys[12] == vector(K13)


def test_compress_of_a2():
    h = compress(0, 0, vector(M1_PADDED))
    assert h == vector(H1_AFTER_G_N)
    assert compress(0, h, N1) == vector(H1_AFTER_G0_N)


# No GOST examples exist for these lengths; expected values were computed with
# the independent verification tool from milestone M0, not taken from the standard.
H_EMPTY = (
    "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7"
    "362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a"
)
H_ONE_BLOCK = (
    "2ae581f18ae85e3596c936acbef910f2ed70dcf91ed5d24b39a5af657bf8232a"
    "303d686056c8c00bf30d42e16ce255426fa8a155dcb3eb822d925808f7c7e345"
)
H_TWO_BLOCKS = (
    "a8d65e689c89d8cd4616215d14ebfc02993bde3f5c7d7219904d87848ce9249e"
    "7ce3525ae605d85a3596457c880f938eead974b91f61203d31665ca6f3a1decc"
)
H_THREE_BLOCKS_OF_FF_PLUS_TAIL = (
    "a32bc44c32d9f7fc60d133fbddd468fc49e43253bcce4d90befcdbe5d4899d46"
    "a54ca52f416ed90cd74c46a5e1d67932b5e8350370424e6918ab80a19ffc97c6"
)


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"", H_EMPTY),
        (bytes(range(64)), H_ONE_BLOCK),
        (bytes(range(128)), H_TWO_BLOCKS),
        (b"\xff" * 200, H_THREE_BLOCKS_OF_FF_PLUS_TAIL),
    ],
    ids=["empty", "exactly-one-block", "exactly-two-blocks", "sigma-overflows-2^512"],
)
def test_block_boundaries(data, expected):
    assert streebog512(data) == bytes.fromhex(expected)


def test_digest_is_64_bytes():
    assert len(streebog512(b"x")) == 64
