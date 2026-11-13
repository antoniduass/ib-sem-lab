import base64
import io
import re

import pytest

from app.recovery import ALPHABET, recovery_hash
from tests.conftest import PASSWORD, last_code


@pytest.fixture
def to_key_step(submit, outbox):
    def run(login="anton"):
        assert (
            submit("/login", {"login": login, "password": PASSWORD}).status_code == 302
        )
        assert submit("/login/code", {"code": last_code(outbox)}).status_code == 302

    return run


def codes_left(client):
    page = client.get("/account").get_data(as_text=True)
    return int(re.search(r'id="codes-left">(\d+)<', page).group(1))


def test_registration_shows_ten_distinct_codes_stored_as_hashes(
    register, recovery_codes, query
):
    register()
    codes = recovery_codes["anton"]
    assert len(codes) == 10 and len(set(codes)) == 10
    for code in codes:
        assert re.fullmatch(f"[{ALPHABET}]{{5}}-[{ALPHABET}]{{5}}", code)
    stored = {
        row[0]
        for row in query("SELECT code_hash FROM recovery_codes WHERE user_id = 1")
    }
    assert stored == {recovery_hash(1, code) for code in codes}
    assert all(
        code.replace("-", "").encode() not in repr(stored).encode() for code in codes
    )


def test_recovery_code_replaces_email_code(client, register, recovery_codes, submit):
    register()
    submit("/login", {"login": "anton", "password": PASSWORD})
    assert (
        submit("/login/code", {"code": recovery_codes["anton"][0]}).status_code == 302
    )
    page = client.get("/login/key").get_data(as_text=True)
    assert "Потеряли файл ключа?" not in page


def test_only_one_recovery_code_per_login(client, register, recovery_codes, submit):
    register()
    submit("/login", {"login": "anton", "password": PASSWORD})
    submit("/login/code", {"code": recovery_codes["anton"][0]})
    response = submit("/login/key", {"recovery_code": recovery_codes["anton"][1]})
    assert response.status_code == 400
    assert client.get("/account").status_code == 302


def test_recovery_code_replaces_key_file(
    client, register, recovery_codes, submit, to_key_step
):
    register()
    to_key_step()
    response = submit(
        "/login/key", {"recovery_code": recovery_codes["anton"][0].lower()}
    )
    assert response.headers["Location"].endswith("/account")
    page = client.get("/account").get_data(as_text=True)
    assert "Выпустите новый файл ключа" in page
    assert codes_left(client) == 9


def test_recovery_code_is_single_use(
    app, register, recovery_codes, submit, to_key_step
):
    register()
    code = recovery_codes["anton"][0]
    to_key_step()
    submit("/login/key", {"recovery_code": code})
    other = app.test_client()
    page = other.get("/login").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    other.post(
        "/login", data={"login": "anton", "password": PASSWORD, "csrf_token": token}
    )
    page = other.get("/login/code").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    assert (
        other.post("/login/code", data={"code": code, "csrf_token": token}).status_code
        == 400
    )


def test_recovery_code_of_another_user_is_rejected(register, recovery_codes, submit):
    register()
    register("boss")
    submit("/login", {"login": "anton", "password": PASSWORD})
    assert submit("/login/code", {"code": recovery_codes["boss"][0]}).status_code == 400


def test_new_recovery_codes_replace_old_ones(
    client, register, log_in, recovery_codes, submit
):
    register()
    log_in()
    response = submit("/account/recovery-codes", {}, form_url="/account")
    new_codes = re.findall(
        r"<code>([A-Z0-9-]{11})</code>", response.get_data(as_text=True)
    )
    assert len(new_codes) == 10 and not set(new_codes) & set(recovery_codes["anton"])
    assert codes_left(client) == 10
    submit("/logout", {}, form_url="/account")
    submit("/login", {"login": "anton", "password": PASSWORD})
    assert (
        submit("/login/code", {"code": recovery_codes["anton"][0]}).status_code == 400
    )
    assert submit("/login/code", {"code": new_codes[0]}).status_code == 302


def test_new_signing_key_replaces_old_file(register, log_in, submit, to_key_step):
    old_key = register()
    log_in()
    response = submit("/account/signing-key", {}, form_url="/account")
    encoded = re.search(r"base64,([^\"]+)\"", response.get_data(as_text=True)).group(1)
    new_key = base64.b64decode(encoded)
    submit("/logout", {}, form_url="/account")
    to_key_step()
    old = submit("/login/key", {"key_file": (io.BytesIO(old_key), "k.json")})
    assert old.status_code == 400
    new = submit("/login/key", {"key_file": (io.BytesIO(new_key), "k.json")})
    assert new.headers["Location"].endswith("/account")


@pytest.mark.parametrize("url", ["/account/recovery-codes", "/account/signing-key"])
def test_account_actions_require_login(client, url):
    client.get("/login")
    page = client.get("/login").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    assert (
        client.post(url, data={"csrf_token": token})
        .headers["Location"]
        .endswith("/login")
    )
