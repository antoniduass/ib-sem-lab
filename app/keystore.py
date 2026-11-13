"""Server secrets at rest: the master key lives in a file under `instance/`;
other keys are stored wrapped by it with Kuznyechik in counter mode (GOST 34.13)."""

import os
import secrets
from pathlib import Path

from flask import current_app

from gostcrypto.ctr import IV_BYTES, ctr_decrypt, ctr_encrypt
from gostcrypto.kuznyechik import KEY_BYTES
from gostcrypto.rsa import PrivateKey, load_private_key


def master_key() -> bytes:
    configured = current_app.config.get("MASTER_KEY")
    if configured is not None:
        return configured
    path = Path(current_app.config["MASTER_KEY_PATH"])
    if not path.exists():
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as file:
            file.write(secrets.token_bytes(KEY_BYTES))
    return path.read_bytes()


def wrap(data: bytes) -> bytes:
    iv = secrets.token_bytes(IV_BYTES)
    return iv + ctr_encrypt(master_key(), iv, data)


def unwrap(blob: bytes) -> bytes:
    return ctr_decrypt(master_key(), blob[:IV_BYTES], blob[IV_BYTES:])


def system_rsa_key() -> PrivateKey:
    configured = current_app.config.get("RSA_KEY")
    if configured is not None:
        return configured
    return load_private_key(current_app.config["RSA_KEY_PATH"])
