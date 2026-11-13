import os

from app import create_app
from app.keystore import master_key, unwrap, wrap
from app.signing_keys import read_key_file
from gostcrypto.ctr import ctr_encrypt


def test_wrap_round_trip_with_random_iv(app):
    with app.app_context():
        first, second = wrap(b"secret"), wrap(b"secret")
        assert first != second
        assert unwrap(first) == unwrap(second) == b"secret"
        assert first[8:] == ctr_encrypt(bytes(range(32)), first[:8], b"secret")


def test_master_key_file_is_created_once_with_private_permissions(tmp_path):
    path = tmp_path / "master_key.bin"
    app = create_app({"MASTER_KEY_PATH": str(path)})
    with app.app_context():
        key = master_key()
        assert len(key) == 32
        assert os.stat(path).st_mode & 0o777 == 0o600
        assert master_key() == key


def test_registration_keeps_wrapped_copy_of_signing_key(app, register, query):
    signing_key = read_key_file(register())
    [(wrapped,)] = query("SELECT signing_key_encrypted FROM users")
    assert signing_key.to_bytes(64, "big") not in wrapped
    with app.app_context():
        assert int.from_bytes(unwrap(wrapped), "big") == signing_key
