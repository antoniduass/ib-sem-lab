import os

import pytest

from app import create_app
from app.keystore import demo_rsa_key

# GOST 34.11-2018, A.2.1: hash of M1, written most significant byte first
M1_HASH_512 = (
    "486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00"
    "fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b"
)
# GOST 34.13-2018, A.2.3, table A.2: ciphertext of the counter mode example
CTR_CIPHERTEXT = (
    "f195d8bec10ed1dbd57b5fa240bda1b885eee733f6a13e5df33ce4b33c45dee4"
    "a5eae88be6356ed3d5e877f13564a3a5cb91fab1f20cbab6d1c6d15820bdba73"
)


@pytest.fixture
def run(submit):
    def post(action, **fields):
        return submit("/demo", {"action": action, **fields})

    return post


def test_demo_is_open_to_guests_with_prefilled_examples(client):
    page = client.get("/demo").get_data(as_text=True)
    assert "012345678901234567890123456789012345678901234567890123456789012" in page
    assert "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef" in page


def test_streebog_demo_matches_gost_example(run):
    page = run("streebog").get_data(as_text=True)
    assert f'<pre id="streebog-standard">{M1_HASH_512}</pre>' in page


def test_kuznyechik_demo_matches_gost_example(run):
    page = run("kuznyechik").get_data(as_text=True)
    assert f'<pre id="kuznyechik-ciphertext">{CTR_CIPHERTEXT}</pre>' in page


@pytest.mark.parametrize(
    ("field", "value"),
    [("key", "zz"), ("key", "00" * 31), ("iv", "00" * 9), ("plaintext", "abc")],
)
def test_kuznyechik_demo_rejects_bad_input(run, field, value):
    response = run("kuznyechik", **{field: value})
    assert response.status_code == 400
    assert 'id="demo-error"' in response.get_data(as_text=True)


def test_rsa_demo_round_trip(run, test_rsa_key):
    page = run("rsa", rsa_text="Проверка RSA").get_data(as_text=True)
    assert '<pre id="rsa-decrypted">Проверка RSA</pre>' in page
    assert f"Модуль: {test_rsa_key.n.bit_length()} бит" in page


def test_rsa_demo_rejects_unknown_key(run):
    assert run("rsa", rsa_key="other").status_code == 400


def test_demo_key_is_generated_once(tmp_path):
    path = tmp_path / "demo.json"
    app = create_app({"RSA_DEMO_KEY_PATH": str(path)})
    with app.app_context():
        key = demo_rsa_key()
        assert key.n.bit_length() == 2048
        assert os.stat(path).st_mode & 0o777 == 0o600
        assert demo_rsa_key() == key
