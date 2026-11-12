import pytest

from gostcrypto.ctr import ctr_decrypt, ctr_encrypt
from gostcrypto.kuznyechik import encrypt_block

h = bytes.fromhex

# GOST 34.13-2018, A.2.1 (PDF p. 21): key and plaintext
KEY = h("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
PLAINTEXT_BLOCKS = [
    h("1122334455667700ffeeddccbbaa9988"),
    h("00112233445566778899aabbcceeff0a"),
    h("112233445566778899aabbcceeff0a00"),
    h("2233445566778899aabbcceeff0a0011"),
]

# A.2.3, table A.2 (PDF pp. 21-22). IV is printed with 15 hex digits (defect D2);
# the 64-bit value is taken from the first input block.
IV = h("1234567890abcef0")
COUNTER_BLOCKS = [
    h("1234567890abcef00000000000000000"),
    h("1234567890abcef00000000000000001"),
    h("1234567890abcef00000000000000002"),
    h("1234567890abcef00000000000000003"),
]
GAMMA_BLOCKS = [
    h("e0b7ebfa9468a6db2a95826efb173830"),
    h("85ffc500b2f4582a7ba54e08f0ab21ee"),
    h("b4c8dbcfb353195b4c42cc3ddb9ba9a5"),
    h("e9a2bee4947b322f7b7d1db6dfb7ba62"),
]
CIPHERTEXT_BLOCKS = [
    h("f195d8bec10ed1dbd57b5fa240bda1b8"),
    h("85eee733f6a13e5df33ce4b33c45dee4"),
    h("a5eae88be6356ed3d5e877f13564a3a5"),
    h("cb91fab1f20cbab6d1c6d15820bdba73"),
]
PLAINTEXT = b"".join(PLAINTEXT_BLOCKS)
CIPHERTEXT = b"".join(CIPHERTEXT_BLOCKS)


def test_first_counter_is_iv_followed_by_zeros():
    assert COUNTER_BLOCKS[0] == IV + bytes(8)


@pytest.mark.parametrize("i", range(4))
def test_gamma_is_encrypted_counter(i):
    assert encrypt_block(KEY, COUNTER_BLOCKS[i]) == GAMMA_BLOCKS[i]


def test_encrypt_matches_table_a_2():
    assert ctr_encrypt(KEY, IV, PLAINTEXT) == CIPHERTEXT


def test_decrypt_matches_table_a_2():
    assert ctr_decrypt(KEY, IV, CIPHERTEXT) == PLAINTEXT


@pytest.mark.parametrize("length", [0, 1, 15, 16, 17, 33, 63])
def test_partial_message_uses_leading_gamma_bytes(length):
    ciphertext = ctr_encrypt(KEY, IV, PLAINTEXT[:length])
    assert ciphertext == CIPHERTEXT[:length]
    assert ctr_decrypt(KEY, IV, ciphertext) == PLAINTEXT[:length]


def test_long_message_round_trip():
    message = bytes(range(256)) * 5
    ciphertext = ctr_encrypt(KEY, IV, message)
    assert len(ciphertext) == len(message)
    assert ciphertext != message
    assert ctr_decrypt(KEY, IV, ciphertext) == message


def test_different_iv_gives_different_ciphertext():
    other_iv = bytes(8)
    assert ctr_encrypt(KEY, other_iv, PLAINTEXT) != CIPHERTEXT


def test_counter_increments_across_low_byte_carry():
    iv = bytes(8)
    block = bytes(16)
    gamma_255 = encrypt_block(KEY, iv + (255).to_bytes(8, "big"))
    gamma_256 = encrypt_block(KEY, iv + (256).to_bytes(8, "big"))
    ciphertext = ctr_encrypt(KEY, iv, block * 257)
    assert ciphertext[255 * 16 : 256 * 16] == gamma_255
    assert ciphertext[256 * 16 :] == gamma_256


@pytest.mark.parametrize("iv", [b"", bytes(7), bytes(9), bytes(16)])
def test_rejects_wrong_iv_length(iv):
    with pytest.raises(ValueError):
        ctr_encrypt(KEY, iv, PLAINTEXT)


def test_rejects_wrong_key_length():
    with pytest.raises(ValueError):
        ctr_encrypt(KEY[:31], IV, PLAINTEXT)
