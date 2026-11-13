import pytest

from app.db import get_db
from app.sessions import COOKIE_NAME, token_hash
from tests.conftest import PASSWORD


def session_cookie(client):
    cookie = client.get_cookie(COOKIE_NAME)
    return cookie.value if cookie else None


def test_successful_login_opens_account(client, register, log_in):
    register()
    response = log_in()
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/account")
    page = client.get("/account").get_data(as_text=True)
    assert "anton" in page and "пользователь" in page


@pytest.mark.parametrize(
    ("login", "password"),
    [("anton", PASSWORD + "x"), ("nobody", PASSWORD), ("anton", "")],
)
def test_failed_login_gives_one_generic_message(
    client, register, log_in, login, password
):
    register()
    response = log_in(login, password)
    assert response.status_code == 400
    assert "Неверный логин или пароль." in response.get_data(as_text=True)
    assert client.get("/account").status_code == 302


def test_login_is_case_insensitive(client, register, log_in):
    register()
    assert log_in("ANTON").status_code == 302


def test_session_cookie_is_random_http_only_and_stored_hashed(
    client, register, log_in, query
):
    register()
    log_in()
    token = session_cookie(client)
    cookie = client.get_cookie(COOKIE_NAME)
    assert len(token) >= 43
    assert cookie.http_only and cookie.same_site == "Lax"
    [(stored_hash, data)] = query("SELECT token_hash, data FROM sessions")
    assert stored_hash == token_hash(token)
    assert token.encode() not in stored_hash
    assert data["user_id"] == 1


def test_login_rotates_session_token(client, register, log_in, query):
    register()
    client.get("/login")
    before = session_cookie(client)
    assert before is not None
    log_in()
    after = session_cookie(client)
    assert after != before
    assert (
        query("SELECT 1 FROM sessions WHERE token_hash = %s", (token_hash(before),))
        == []
    )


def test_logout_deletes_server_session(client, register, log_in, submit, query):
    register()
    log_in()
    token = session_cookie(client)
    response = submit("/logout", {}, form_url="/account")
    assert response.status_code == 302
    assert (
        query("SELECT 1 FROM sessions WHERE token_hash = %s", (token_hash(token),))
        == []
    )
    assert client.get("/account").status_code == 302


def test_stolen_cookie_is_useless_after_logout(app, client, register, log_in, submit):
    register()
    log_in()
    token = session_cookie(client)
    submit("/logout", {}, form_url="/account")
    attacker = app.test_client()
    attacker.set_cookie(COOKIE_NAME, token)
    assert attacker.get("/account").status_code == 302


def test_expired_session_is_ignored(client, register, log_in, query, app):
    register()
    log_in()
    with app.app_context():
        get_db().execute("UPDATE sessions SET expires_at = now() - interval '1 second'")
    assert client.get("/account").status_code == 302


def test_unknown_session_cookie_is_ignored(client):
    client.set_cookie(COOKIE_NAME, "forged-token")
    assert client.get("/account").status_code == 302


def test_guest_gets_no_session_row(client, query):
    client.get("/")
    client.get("/health")
    assert query("SELECT 1 FROM sessions") == []
    assert session_cookie(client) is None


@pytest.mark.parametrize("url", ["/register", "/login", "/logout"])
def test_post_without_csrf_token_is_rejected(client, url):
    client.get("/login")
    assert client.post(url, data={"login": "anton"}).status_code == 400


def test_post_with_foreign_csrf_token_is_rejected(app, client, register):
    register()
    other = app.test_client()
    page = other.get("/login").get_data(as_text=True)
    foreign = page.split('name="csrf_token" value="')[1].split('"')[0]
    client.get("/login")
    response = client.post(
        "/login", data={"login": "anton", "password": PASSWORD, "csrf_token": foreign}
    )
    assert response.status_code == 400


@pytest.mark.parametrize("url", ["/account", "/admin"])
def test_guest_is_redirected_to_login(client, url):
    response = client.get(url)
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_user_cannot_open_admin_page(client, register, log_in):
    register()
    log_in()
    assert client.get("/admin").status_code == 403
    assert "Администрирование" not in client.get("/account").get_data(as_text=True)


def test_admin_sees_admin_page(app, client, register, log_in):
    register()
    register("boss")
    result = app.test_cli_runner().invoke(args=["set-role", "Boss", "admin"])
    assert result.exit_code == 0
    log_in("boss")
    page = client.get("/admin").get_data(as_text=True)
    assert client.get("/admin").status_code == 200
    assert "anton@example.com" in page and "boss@example.com" in page


def test_role_change_applies_to_open_session(app, client, register, log_in):
    register()
    log_in()
    runner = app.test_cli_runner()
    runner.invoke(args=["set-role", "anton", "admin"])
    assert client.get("/admin").status_code == 200
    runner.invoke(args=["set-role", "anton", "user"])
    assert client.get("/admin").status_code == 403


def test_set_role_rejects_unknown_user_and_role(app):
    runner = app.test_cli_runner()
    assert runner.invoke(args=["set-role", "ghost", "admin"]).exit_code != 0
    assert runner.invoke(args=["set-role", "ghost", "root"]).exit_code != 0


def test_navigation_depends_on_role(app, client, register, log_in):
    assert "Вход" in client.get("/").get_data(as_text=True)
    register()
    log_in()
    page = client.get("/").get_data(as_text=True)
    assert "Выйти" in page and "Администрирование" not in page
    app.test_cli_runner().invoke(args=["set-role", "anton", "admin"])
    assert "Администрирование" in client.get("/").get_data(as_text=True)


def test_post_with_empty_csrf_token_and_no_session_is_rejected(client):
    assert client.post("/logout", data={"csrf_token": ""}).status_code == 400


def test_login_replaces_guest_csrf_token(client, register, log_in):
    register()
    guest_page = client.get("/login").get_data(as_text=True)
    log_in()
    user_page = client.get("/account").get_data(as_text=True)
    marker = 'name="csrf_token" value="'
    guest_token = guest_page.split(marker)[1].split('"')[0]
    user_token = user_page.split(marker)[1].split('"')[0]
    assert guest_token != user_token
