"""Counter (gamma) mode of GOST 34.13-2018, section 5.2, with Kuznyechik and s = n = 128.

Data, IV and counters are bytes in the order the standard writes its hex vectors.
"""

from gostcrypto.kuznyechik import (
    BLOCK_BYTES,
    encrypt_with_round_keys,
    require_length,
    round_keys,
)

IV_BYTES = BLOCK_BYTES // 2


def ctr_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    require_length(iv, IV_BYTES, "iv")
    keys = round_keys(key)
    counter = int.from_bytes(iv, "big") << (8 * IV_BYTES)
    output = bytearray()
    for offset in range(0, len(data), BLOCK_BYTES):
        gamma = encrypt_with_round_keys(keys, counter.to_bytes(BLOCK_BYTES, "big"))
        chunk = data[offset : offset + BLOCK_BYTES]
        # zip stops at the chunk length: the last block takes MSB_r of the gamma (formula 4)
        output += bytes(x ^ y for x, y in zip(chunk, gamma))
        counter += 1
    return bytes(output)


ctr_decrypt = ctr_encrypt
