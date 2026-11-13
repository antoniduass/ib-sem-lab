import re

import pytest

from app.db import get_db
from tests.conftest import PASSWORD, last_code

NEW_PASSWORD = "N3w!Passw0rd-2026"


@pytest.fixture
def request_reset(submit):
    def run(email="anton@example.com"):
        return submit("/reset", {"email": email})

    return run


@pytest.fixture
def confirm_reset(submit):
    def run(code, password=NEW_PASSWORD, confirm=None):
        return submit(
            "/reset/confirm",
            {
                "code": code,
                "password": password,
                "password_confirm": password if confirm is None else confirm,
            },
        )

    return run


def test_reset_with_email_code_changes_password(
    app, register, log_in, request_reset, confirm_reset, outbox
):
    register()
    response = request_reset()
    assert response.headers["Location"].endswith("/reset/confirm")
    to, subject, _ = outbox[-1]
    assert (to, subject) == ("anton@example.com", "Код для сброса пароля")
    response = confirm_reset(last_code(outbox))
    assert response.headers["Location"].endswith("/login")
    assert log_in(password=PASSWORD).status_code == 400
    assert log_in(password=NEW_PASSWORD).headers["Location"].endswith("/account")


def test_reset_does_not_reveal_unknown_email(client, request_reset, outbox):
    response = request_reset("nobody@example.com")
    assert response.headers["Location"].endswith("/reset/confirm")
    assert outbox == []
    page = client.get("/reset/confirm").get_data(as_text=True)
    assert "Если такой email зарегистрирован" in page


def test_reset_with_recovery_code(
    register, recovery_codes, log_in, request_reset, confirm_reset
):
    register()
    request_reset()
    response = confirm_reset(recovery_codes["anton"][3])
    assert response.headers["Location"].endswith("/login")
    assert log_in(password=NEW_PASSWORD).headers["Location"].endswith("/account")


def test_reset_rejects_weak_password_without_spending_code(
    register, request_reset, confirm_reset, outbox
):
    register()
    request_reset()
    code = last_code(outbox)
    assert confirm_reset(code, password="weak").status_code == 400
    assert confirm_reset(code, confirm=NEW_PASSWORD + "x").status_code == 400
    assert confirm_reset(code).headers["Location"].endswith("/login")


def test_login_code_cannot_reset_password(
    register, submit, request_reset, confirm_reset, outbox
):
    register()
    submit("/login", {"login": "anton", "password": PASSWORD})
    login_code = last_code(outbox)
    request_reset()
    reset_code = last_code(outbox)
    if login_code != reset_code:
        assert confirm_reset(login_code).status_code == 400


def test_expired_reset_code_is_rejected(
    app, register, request_reset, confirm_reset, outbox
):
    register()
    request_reset()
    with app.app_context():
        get_db().execute(
            "UPDATE one_time_codes SET expires_at = now() - interval '1 second'"
        )
    assert confirm_reset(last_code(outbox)).status_code == 400


def test_five_wrong_reset_codes_restart(
    client, register, request_reset, confirm_reset, outbox
):
    register()
    request_reset()
    real = last_code(outbox)
    wrong = "000000" if real != "000000" else "111111"
    for _ in range(4):
        assert confirm_reset(wrong).status_code == 400
    assert confirm_reset(wrong).headers["Location"].endswith("/reset")
    assert client.get("/reset/confirm").headers["Location"].endswith("/reset")


def test_reset_confirm_requires_request(client):
    assert client.get("/reset/confirm").headers["Location"].endswith("/reset")


def test_reset_logs_out_existing_sessions(
    app, register, log_in, client, request_reset, confirm_reset, outbox, submit
):
    register()
    log_in()
    assert client.get("/account").status_code == 200
    reset_client = app.test_client()
    page = reset_client.get("/reset").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    reset_client.post(
        "/reset", data={"email": "anton@example.com", "csrf_token": token}
    )
    page = reset_client.get("/reset/confirm").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    response = reset_client.post(
        "/reset/confirm",
        data={
            "code": last_code(outbox),
            "password": NEW_PASSWORD,
            "password_confirm": NEW_PASSWORD,
            "csrf_token": token,
        },
    )
    assert response.headers["Location"].endswith("/login")
    assert client.get("/account").status_code == 302
