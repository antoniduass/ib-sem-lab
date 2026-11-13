import io
import re

import pytest

from app.db import get_db
from tests.conftest import PASSWORD, last_code


@pytest.fixture
def admin(app, register, log_in):
    register()
    register("boss")
    app.test_cli_runner().invoke(args=["set-role", "boss", "admin"])
    log_in("boss")


@pytest.fixture
def act(submit):
    def run(path, **data):
        return submit(f"/admin/users/{path}", data, form_url="/admin")

    return run


def user_row(query, login):
    [row] = query("SELECT role, is_blocked FROM users WHERE login = %s", (login,))
    return row


def other_client_logged_in(app, login, key_file, outbox):
    other = app.test_client()

    def post(url, data):
        page = other.get(url).get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
        return other.post(url, data={**data, "csrf_token": token})

    post("/login", {"login": login, "password": PASSWORD})
    post("/login/code", {"code": last_code(outbox)})
    post("/login/key", {"key_file": (io.BytesIO(key_file), "k.json")})
    return other


def test_admin_sees_all_users(admin, client):
    page = client.get("/admin").get_data(as_text=True)
    assert "anton@example.com" in page and "boss@example.com" in page
    assert "boss (вы)" not in page and "admin (вы)" in page


def test_admin_changes_role(admin, act, query):
    assert act("1/role", role="admin").headers["Location"].endswith("/admin")
    assert user_row(query, "anton") == ("admin", False)
    act("1/role", role="user")
    assert user_row(query, "anton") == ("user", False)


def test_invalid_role_is_rejected(admin, act, query):
    assert act("1/role", role="root").status_code == 400
    assert user_row(query, "anton") == ("user", False)


def test_admin_cannot_demote_or_block_self(admin, act, query, client):
    act("2/role", role="user")
    act("2/block")
    assert user_row(query, "boss") == ("admin", False)
    assert "Нельзя менять роль" in client.get("/admin").get_data(as_text=True)


def test_unknown_user_gives_404(admin, act):
    assert act("99/block").status_code == 404


def test_blocking_ends_sessions_and_prevents_login(
    app, register, log_in, act, key_files, outbox, query, submit, client
):
    register()
    victim = other_client_logged_in(app, "anton", key_files["anton"], outbox)
    assert victim.get("/account").status_code == 200
    register("boss")
    app.test_cli_runner().invoke(args=["set-role", "boss", "admin"])
    log_in("boss")
    act("1/block")
    assert user_row(query, "anton") == ("user", True)
    assert victim.get("/account").status_code == 302
    submit("/logout", {}, form_url="/account")
    response = submit("/login", {"login": "anton", "password": PASSWORD})
    assert response.status_code == 400
    assert "заблокирована" in response.get_data(as_text=True)


def test_unblocked_user_can_log_in_again(admin, act, submit, query):
    act("1/block")
    act("1/unblock")
    assert user_row(query, "anton") == ("user", False)
    submit("/logout", {}, form_url="/account")
    assert submit("/login", {"login": "anton", "password": PASSWORD}).status_code == 302


def test_user_cannot_use_admin_actions(register, log_in, submit, client, query):
    register()
    register("other")
    log_in()
    for path in ["2/block", "2/unblock"]:
        response = submit(f"/admin/users/{path}", {}, form_url="/account")
        assert response.status_code == 403
    response = submit("/admin/users/1/role", {"role": "admin"}, form_url="/account")
    assert response.status_code == 403
    assert user_row(query, "anton") == ("user", False)
    assert client.get("/admin/log").status_code == 403


def test_guest_is_sent_to_login(client):
    assert client.get("/admin/log").headers["Location"].endswith("/login")


def test_login_journal_records_events(
    app, register, log_in, submit, outbox, client, query
):
    register()
    submit("/login", {"login": "ghost", "password": PASSWORD})
    submit("/login", {"login": "anton", "password": PASSWORD})
    submit("/login/code", {"code": "abc"})
    submit("/login/code", {"code": last_code(outbox)})
    submit("/login/key", {"recovery_code": "AAAAA-AAAAA"})
    log_in()
    events = query("SELECT login, event FROM login_events ORDER BY id")
    assert events == [
        ("ghost", "password_failed"),
        ("anton", "code_failed"),
        ("anton", "key_failed"),
        ("anton", "success"),
    ]
    app.test_cli_runner().invoke(args=["set-role", "anton", "admin"])
    page = client.get("/admin/log").get_data(as_text=True)
    assert "неверный логин или пароль" in page and "успешный вход" in page


def test_blocked_attempt_is_logged(admin, act, submit, query):
    act("1/block")
    submit("/logout", {}, form_url="/account")
    submit("/login", {"login": "anton", "password": PASSWORD})
    assert query("SELECT login, event FROM login_events ORDER BY id DESC LIMIT 1") == [
        ("anton", "blocked")
    ]


def test_blocking_deletes_user_sessions_from_database(
    app, register, log_in, act, key_files, outbox, query
):
    register()
    other_client_logged_in(app, "anton", key_files["anton"], outbox)
    assert query("SELECT 1 FROM sessions WHERE data->>'user_id' = '1'") != []
    register("boss")
    app.test_cli_runner().invoke(args=["set-role", "boss", "admin"])
    log_in("boss")
    act("1/block")
    assert query("SELECT 1 FROM sessions WHERE data->>'user_id' = '1'") == []


def test_blocked_flag_alone_ends_open_session(app, register, key_files, outbox):
    register()
    victim = other_client_logged_in(app, "anton", key_files["anton"], outbox)
    with app.app_context():
        get_db().execute("UPDATE users SET is_blocked = true WHERE id = 1")
    assert victim.get("/account").status_code == 302
