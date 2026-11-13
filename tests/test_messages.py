import base64
import io
import json
import re

import pytest

from app.keystore import unwrap
from app.pdf import MARKER, extract_signed_data
from app.signing_keys import decode_public_key, decode_signature
from gostcrypto import rsa
from gostcrypto.ctr import ctr_decrypt
from gostcrypto.gost3410 import PARAMSET_512_A, verify

TEXT = "Секретная заметка: встреча в 18:00."


@pytest.fixture
def user(register, log_in):
    register()
    log_in()


@pytest.fixture
def write(submit):
    def run(text=TEXT, algorithm="kuznyechik"):
        return submit("/messages/new", {"text": text, "algorithm": algorithm})

    return run


def stored_messages(query):
    return query(
        "SELECT id, payload, wrapped_key, signature, signer_public_key FROM messages ORDER BY id"
    )


def decrypt_page(submit, message_id):
    return submit(f"/messages/{message_id}/decrypt", {}, form_url="/messages")


@pytest.mark.parametrize("algorithm", ["kuznyechik", "rsa"])
def test_message_is_stored_encrypted_and_decrypts(
    user, write, submit, query, algorithm
):
    assert write(algorithm=algorithm).headers["Location"].endswith("/messages")
    [(message_id, payload, wrapped_key, _, _)] = stored_messages(query)
    fields = json.loads(payload)
    assert fields["algorithm"] == algorithm and fields["author"] == "anton"
    assert TEXT.encode() not in payload and TEXT.encode() not in (wrapped_key or b"")
    page = decrypt_page(submit, message_id).get_data(as_text=True)
    assert f'<pre id="plaintext">{TEXT}</pre>' in page


def test_kuznyechik_message_uses_wrapped_per_message_key(app, user, write, query):
    write()
    write()
    rows = stored_messages(query)
    keys = []
    with app.app_context():
        for _, payload, wrapped_key, _, _ in rows:
            fields = json.loads(payload)
            key = unwrap(wrapped_key)
            iv = base64.b64decode(fields["iv"])
            ciphertext = base64.b64decode(fields["ciphertext"])
            assert ctr_decrypt(key, iv, ciphertext) == TEXT.encode()
            keys.append(key)
    assert keys[0] != keys[1]
    assert json.loads(rows[0][1])["ciphertext"] != json.loads(rows[1][1])["ciphertext"]


def test_rsa_message_uses_system_key(test_rsa_key, user, write, query):
    write(algorithm="rsa")
    [(_, payload, wrapped_key, _, _)] = stored_messages(query)
    ciphertext = base64.b64decode(json.loads(payload)["ciphertext"])
    assert wrapped_key is None
    assert len(ciphertext) == rsa.modulus_bytes(test_rsa_key.n)
    assert rsa.decrypt(test_rsa_key, ciphertext) == TEXT.encode()


def test_message_is_signed_with_author_key(user, write, query):
    write()
    [(_, payload, _, signature, signer_key)] = stored_messages(query)
    [(current_key,)] = query("SELECT signing_public_key FROM users")
    assert signer_key == current_key
    public_key = decode_public_key(signer_key)
    assert verify(PARAMSET_512_A, public_key, payload, decode_signature(signature))


@pytest.mark.parametrize(
    ("text", "algorithm"),
    [("", "kuznyechik"), ("   ", "rsa"), ("a" * 4001, "kuznyechik"), (TEXT, "magma")],
)
def test_invalid_message_is_rejected(user, write, query, text, algorithm):
    assert write(text, algorithm).status_code == 400
    assert stored_messages(query) == []


def test_limit_counts_bytes_not_characters(user, write, query):
    assert write("ж" * 2000).status_code == 302
    assert write("ж" * 2001).status_code == 400


@pytest.mark.parametrize("url", ["/messages", "/messages/new", "/messages/1/pdf"])
def test_guest_is_sent_to_login(client, url):
    assert client.get(url).headers["Location"].endswith("/login")


def test_other_users_messages_are_hidden(
    app, register, log_in, write, submit, client, query
):
    register()
    register("boss")
    log_in("boss")
    write("boss secret")
    submit("/logout", {}, form_url="/account")
    log_in()
    assert "Сообщений пока нет." in client.get("/messages").get_data(as_text=True)
    assert decrypt_page(submit, 1).status_code == 404
    assert client.get("/messages/1/pdf").status_code == 404


def test_pdf_contains_verifiable_signature(user, write, client, query):
    write()
    response = client.get("/messages/1/pdf")
    assert response.mimetype == "application/pdf"
    assert "message-1.pdf" in response.headers["Content-Disposition"]
    content = response.get_data()
    assert content.startswith(b"%PDF")
    data = extract_signed_data(content)
    [(_, payload, _, signature, signer_key)] = stored_messages(query)
    assert base64.b64decode(data["payload"]) == payload
    assert data["signature"] == signature.hex()
    assert data["public_key"] == signer_key.hex()


@pytest.fixture
def check(submit):
    def run(content):
        return submit("/verify", {"pdf_file": (io.BytesIO(content), "m.pdf")})

    return run


def test_verify_page_accepts_genuine_pdf(user, write, client, check):
    write()
    page = check(client.get("/messages/1/pdf").get_data()).get_data(as_text=True)
    assert "Подпись верна." in page and "anton" in page
    assert "совпадает с текущим ключом" in page


def tamper(content, change):
    match = re.search((MARKER + "([A-Za-z0-9+/=]+)").encode(), content)
    data = json.loads(base64.b64decode(match.group(1)))
    change(data)
    new = base64.b64encode(json.dumps(data).encode())
    return content.replace(match.group(1), new)


def edit_payload(data):
    fields = json.loads(base64.b64decode(data["payload"]))
    fields["author"] = "mallory"
    data["payload"] = base64.b64encode(json.dumps(fields).encode()).decode()


def flip_signature(data):
    data["signature"] = ("0" if data["signature"][0] != "0" else "1") + data[
        "signature"
    ][1:]


def other_key(data):
    data["public_key"] = data["public_key"][::-1]


@pytest.mark.parametrize("change", [edit_payload, flip_signature, other_key])
def test_verify_rejects_tampered_pdf(user, write, client, check, change):
    write()
    content = tamper(client.get("/messages/1/pdf").get_data(), change)
    response = check(content)
    assert response.status_code == 400
    assert "Подпись неверна" in response.get_data(as_text=True)


@pytest.mark.parametrize(
    "content", [b"", b"not a pdf", b"%PDF-1.3 ib-signed-message:!!!"]
)
def test_verify_rejects_foreign_files(client, check, content):
    response = check(content)
    assert response.status_code == 400


def test_verify_reports_replaced_key(user, write, client, submit, check):
    write()
    content = client.get("/messages/1/pdf").get_data()
    submit("/account/signing-key", {}, form_url="/account")
    page = check(content).get_data(as_text=True)
    assert "Подпись верна." in page and "выпустил новый ключ" in page
    assert client.get("/messages/1/pdf").status_code == 200


def test_guest_can_verify(app, register, log_in, write, client):
    register()
    log_in()
    write()
    content = client.get("/messages/1/pdf").get_data()
    guest = app.test_client()
    page = guest.get("/verify").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    response = guest.post(
        "/verify",
        data={"csrf_token": token, "pdf_file": (io.BytesIO(content), "m.pdf")},
    )
    assert "Подпись верна." in response.get_data(as_text=True)
