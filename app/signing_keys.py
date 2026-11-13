"""User signing keys (GOST 34.10, paramSetA): public key in the database,
private key in a JSON file that the user keeps as the third login factor."""

import json

from gostcrypto.gost3410 import PARAMSET_512_A, Point

CURVE_NAME = "id-tc26-gost-3410-12-512-paramSetA"
KEY_FILE_FORMAT = "ib-sem-lab signing key"
COORDINATE_BYTES = 64


def encode_public_key(point: Point) -> bytes:
    x, y = point
    return x.to_bytes(COORDINATE_BYTES, "big") + y.to_bytes(COORDINATE_BYTES, "big")


def decode_public_key(data: bytes) -> Point:
    return (
        int.from_bytes(data[:COORDINATE_BYTES], "big"),
        int.from_bytes(data[COORDINATE_BYTES:], "big"),
    )


def key_file(login: str, signing_key: int) -> bytes:
    content = {
        "format": KEY_FILE_FORMAT,
        "curve": CURVE_NAME,
        "login": login,
        "private_key": format(signing_key, "x"),
    }
    return json.dumps(content, ensure_ascii=False, indent=2).encode()


def read_key_file(data: bytes) -> int:
    try:
        content = json.loads(data)
        signing_key = int(content["private_key"], 16)
        valid = (
            content["format"] == KEY_FILE_FORMAT
            and content["curve"] == CURVE_NAME
            and 0 < signing_key < PARAMSET_512_A.q
        )
    except (ValueError, TypeError, KeyError):
        valid = False
    if not valid:
        raise ValueError("not a signing key file")
    return signing_key
