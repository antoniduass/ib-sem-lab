import html

from app.passwords import HASH_BYTES, SALT_BYTES, derive_password_hash
from app.validation import EMAIL_PATTERN, LOGIN_PATTERN, PASSWORD_PATTERN

PASSWORD = "Str0ng!Passw0rd"


def form(login="anton", email="anton@example.com", password=PASSWORD, confirm=None):
    return {
        "login": login,
        "email": email,
        "password": password,
        "password_confirm": PASSWORD if confirm is None else confirm,
    }


def test_form_uses_server_patterns_on_client(client):
    page = html.unescape(client.get("/register").get_data(as_text=True))
    for pattern in (LOGIN_PATTERN, EMAIL_PATTERN, PASSWORD_PATTERN):
        assert f'pattern="{pattern}"' in page


def test_registration_stores_salted_hash_only(submit, query, app):
    response = submit("/register", data=form())
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/register/done")
    [(login, email, salt, iterations, password_hash, role)] = query(
        "SELECT login, email, password_salt, password_iterations, password_hash, role FROM users"
    )
    assert (login, email, role) == ("anton", "anton@example.com", "user")
    assert len(salt) == SALT_BYTES and len(password_hash) == HASH_BYTES
    assert iterations == app.config["PASSWORD_ITERATIONS"]
    assert password_hash == derive_password_hash(PASSWORD, salt, iterations)
    stored = b"".join(
        value if isinstance(value, bytes) else str(value).encode()
        for value in query("SELECT * FROM users")[0]
    )
    assert PASSWORD.encode() not in stored


def test_same_password_gives_different_salt_and_hash(submit, query):
    submit("/register", data=form())
    submit("/register", data=form(login="second", email="second@example.com"))
    (salt1, hash1), (salt2, hash2) = query(
        "SELECT password_salt, password_hash FROM users"
    )
    assert salt1 != salt2 and hash1 != hash2


def test_duplicate_login_is_rejected_case_insensitively(submit, query):
    submit("/register", data=form())
    response = submit("/register", data=form(login="ANTON", email="other@example.com"))
    assert response.status_code == 400
    assert "Этот логин уже занят." in response.get_data(as_text=True)
    assert len(query("SELECT id FROM users")) == 1


def test_duplicate_email_is_rejected_case_insensitively(submit, query):
    submit("/register", data=form())
    response = submit("/register", data=form(login="other", email="Anton@Example.com"))
    assert response.status_code == 400
    assert "Этот email уже зарегистрирован." in response.get_data(as_text=True)
    assert len(query("SELECT id FROM users")) == 1


def test_invalid_form_is_rejected_without_storing(submit, query):
    response = submit(
        "/register",
        data=form(login="1bad", email="bad", password="weak", confirm="weak"),
    )
    page = response.get_data(as_text=True)
    assert response.status_code == 400
    assert query("SELECT id FROM users") == []
    assert 'value="1bad"' in page
    assert "weak" not in page.replace('value="1bad"', "")


def test_password_mismatch_is_rejected(submit, query):
    response = submit("/register", data=form(confirm=PASSWORD + "x"))
    assert response.status_code == 400
    assert "Пароли не совпадают." in response.get_data(as_text=True)
    assert query("SELECT id FROM users") == []


def test_init_db_command_is_idempotent(app):
    runner = app.test_cli_runner()
    for _ in range(2):
        result = runner.invoke(args=["init-db"])
        assert result.exit_code == 0
        assert "Database schema is up to date." in result.output
