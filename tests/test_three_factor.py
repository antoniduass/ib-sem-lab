import io
import json

import pytest

from app.codes import code_hash
from app.db import get_db
from app.mail import send_mail as real_send_mail
from app.signing_keys import (
    decode_public_key,
    encode_public_key,
    key_file,
    read_key_file,
)
from gostcrypto.gost3410 import PARAMSET_512_A, multiply_point
from tests.conftest import PASSWORD, last_code


@pytest.fixture
def password_step(submit):
    def run(login="anton"):
        return submit("/login", {"login": login, "password": PASSWORD})

    return run


@pytest.fixture
def code_step(submit):
    def run(code):
        return submit("/login/code", {"code": code})

    return run


@pytest.fixture
def key_step(submit):
    def run(content):
        return submit("/login/key", {"key_file": (io.BytesIO(content), "key.json")})

    return run


def test_registration_gives_key_file_matching_stored_public_key(register, query):
    content = register()
    signing_key = read_key_file(content)
    assert json.loads(content)["login"] == "anton"
    [(public_key,)] = query("SELECT signing_public_key FROM users")
    expected = multiply_point(PARAMSET_512_A, signing_key, PARAMSET_512_A.base_point)
    assert decode_public_key(public_key) == expected


def test_private_key_is_not_stored_on_server(register, query):
    signing_key = read_key_file(register())
    rows = query("SELECT * FROM users") + query("SELECT data::text FROM sessions")
    dump = repr(rows)
    assert format(signing_key, "x") not in dump
    assert signing_key.to_bytes(64, "big").hex() not in dump


def test_password_step_sends_code_and_does_not_log_in(
    client, register, password_step, outbox, query
):
    register()
    response = password_step()
    assert response.headers["Location"].endswith("/login/code")
    to, subject, body = outbox[-1]
    assert to == "anton@example.com"
    assert subject == "Код для входа"
    code = last_code(outbox)
    assert code in body
    [(stored,)] = query("SELECT code_hash FROM one_time_codes WHERE used_at IS NULL")
    assert stored == code_hash(1, code)
    assert code.encode() not in stored
    assert client.get("/account").status_code == 302


def test_full_login_needs_all_three_factors(client, register, log_in):
    register()
    response = log_in()
    assert response.headers["Location"].endswith("/account")
    assert client.get("/account").status_code == 200


@pytest.mark.parametrize("url", ["/login/code", "/login/key"])
def test_steps_cannot_be_opened_directly(client, url):
    response = client.get(url)
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_key_step_cannot_be_reached_without_code(
    client, register, password_step, submit
):
    content = register()
    password_step()
    assert client.get("/login/key").status_code == 302
    response = submit(
        "/login/key",
        {"key_file": (io.BytesIO(content), "key.json")},
        form_url="/login/code",
    )
    assert response.headers["Location"].endswith("/login")
    assert client.get("/account").status_code == 302


def test_wrong_code_is_rejected(register, password_step, code_step, outbox):
    register()
    password_step()
    real = last_code(outbox)
    wrong = f"{(int(real) + 1) % 10**6:06d}"
    response = code_step(wrong)
    assert response.status_code == 400
    assert "Неверный или просроченный код." in response.get_data(as_text=True)
    assert code_step(real).status_code == 302


def test_five_wrong_codes_restart_login(
    client, register, password_step, code_step, outbox
):
    register()
    password_step()
    real = last_code(outbox)
    for _ in range(4):
        assert code_step("000000" if real != "000000" else "111111").status_code == 400
    response = code_step("abc")
    assert response.headers["Location"].endswith("/login")
    assert client.get("/login/code").status_code == 302
    assert "Слишком много" in client.get("/login").get_data(as_text=True)


def test_expired_code_is_rejected(app, register, password_step, code_step, outbox):
    register()
    password_step()
    with app.app_context():
        get_db().execute(
            "UPDATE one_time_codes SET expires_at = now() - interval '1 second'"
        )
    assert code_step(last_code(outbox)).status_code == 400


def test_new_login_invalidates_previous_code(
    register, password_step, code_step, outbox
):
    register()
    password_step()
    first = last_code(outbox)
    password_step()
    second = last_code(outbox)
    if first != second:
        assert code_step(first).status_code == 400
    assert code_step(second).status_code == 302


def test_code_is_single_use(register, log_in, password_step, code_step, outbox):
    register()
    log_in()
    used = last_code(outbox)
    password_step()
    fresh = last_code(outbox)
    if used != fresh:
        assert code_step(used).status_code == 400


def test_code_of_another_user_is_rejected(app, register, password_step, code_step):
    register()
    register("boss")
    password_step("anton")
    with app.app_context():
        get_db().execute(
            "INSERT INTO one_time_codes (user_id, purpose, code_hash, expires_at)"
            " VALUES (2, 'login', %s, now() + interval '5 minutes')",
            (code_hash(2, "123456"),),
        )
    assert code_step("123456").status_code == 400


def test_wrong_key_file_is_rejected(
    client, register, password_step, code_step, key_step, outbox
):
    register()
    other_key = register("boss")
    password_step()
    code_step(last_code(outbox))
    response = key_step(other_key)
    assert response.status_code == 400
    assert "Файл ключа не подходит." in response.get_data(as_text=True)
    assert client.get("/account").status_code == 302


@pytest.mark.parametrize(
    "content",
    [b"", b"not json", b"[]", b'{"format": "x"}', '{"private_key": "ж"}'.encode()],
)
def test_garbage_key_file_is_rejected(
    register, password_step, code_step, key_step, outbox, content
):
    register()
    password_step()
    code_step(last_code(outbox))
    assert key_step(content).status_code == 400


def test_five_wrong_key_files_restart_login(
    client, register, password_step, code_step, key_step, outbox
):
    register()
    password_step()
    code_step(last_code(outbox))
    for _ in range(4):
        assert key_step(b"bad").status_code == 400
    assert key_step(b"bad").headers["Location"].endswith("/login")
    assert client.get("/login/key").status_code == 302


def test_successful_login_rotates_session_after_last_step(
    client, register, password_step, code_step, key_step, outbox
):
    content = register()
    password_step()
    code_step(last_code(outbox))
    before = client.get_cookie("session_id").value
    key_step(content)
    assert client.get_cookie("session_id").value != before


def test_key_file_round_trip_and_validation():
    signing_key = PARAMSET_512_A.q - 1
    assert read_key_file(key_file("anton", signing_key)) == signing_key
    good = json.loads(key_file("anton", 5))
    for change in [
        {"curve": "other"},
        {"format": "other"},
        {"private_key": "0"},
        {"private_key": format(PARAMSET_512_A.q, "x")},
        {"private_key": 5},
    ]:
        with pytest.raises(ValueError):
            read_key_file(json.dumps({**good, **change}).encode())


def test_public_key_encoding_round_trip():
    point = multiply_point(PARAMSET_512_A, 12345, PARAMSET_512_A.base_point)
    assert len(encode_public_key(point)) == 128
    assert decode_public_key(encode_public_key(point)) == point


def test_send_mail_uses_configured_smtp_server(app, monkeypatch):
    sent = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            sent.append((host, port))

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def send_message(self, message):
            sent.append((message["To"], message["Subject"], message.get_content()))

    monkeypatch.setattr("app.mail.smtplib.SMTP", FakeSMTP)
    with app.app_context():
        real_send_mail("anton@example.com", "Тема", "Текст")
    assert sent == [("127.0.0.1", 1025), ("anton@example.com", "Тема", "Текст\n")]


def test_attempt_counter_resets_after_code_step(
    client, register, password_step, code_step, key_step, outbox
):
    register()
    password_step()
    real = last_code(outbox)
    for _ in range(4):
        code_step("000000" if real != "000000" else "111111")
    assert code_step(real).status_code == 302
    for _ in range(4):
        assert key_step(b"bad").status_code == 400
    assert client.get("/login/key").status_code == 200


def test_code_hash_depends_on_user():
    assert code_hash(1, "123456") != code_hash(2, "123456")
    assert len(code_hash(1, "123456")) == 64
