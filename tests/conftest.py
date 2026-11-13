import base64
import io
import os
import re

import pytest

from app import create_app
from app.db import get_db, init_db

PASSWORD = "Str0ng!Passw0rd"
TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL", "postgresql://ib@localhost:5433/ib_test"
)


@pytest.fixture
def app():
    app = create_app(
        {"TESTING": True, "DATABASE_URL": TEST_DATABASE_URL, "PASSWORD_ITERATIONS": 3}
    )
    with app.app_context():
        init_db()
        get_db().execute("TRUNCATE users, sessions, one_time_codes RESTART IDENTITY")
    return app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def query(app):
    def run(sql, params=()):
        with app.app_context():
            return get_db().execute(sql, params).fetchall()

    return run


@pytest.fixture
def submit(client):
    def run(url, data, form_url=None):
        page = client.get(form_url or url).get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
        return client.post(url, data={**data, "csrf_token": token})

    return run


@pytest.fixture(autouse=True)
def outbox(monkeypatch):
    sent = []
    monkeypatch.setattr(
        "app.mail.send_mail", lambda to, subject, body: sent.append((to, subject, body))
    )
    return sent


@pytest.fixture
def key_files():
    return {}


@pytest.fixture
def register(submit, key_files):
    def run(login="anton", email=None, password=PASSWORD):
        response = submit(
            "/register",
            {
                "login": login,
                "email": email or f"{login}@example.com",
                "password": password,
                "password_confirm": password,
            },
        )
        assert response.status_code == 200, response.get_data(as_text=True)
        page = response.get_data(as_text=True)
        encoded = re.search(r'data:application/json;base64,([^"]+)"', page).group(1)
        key_files[login.lower()] = base64.b64decode(encoded)
        return key_files[login.lower()]

    return run


def last_code(outbox):
    return re.search(r"\b\d{6}\b", outbox[-1][2]).group()


@pytest.fixture
def log_in(submit, outbox, key_files):
    def run(login="anton", password=PASSWORD, key_file=None):
        response = submit("/login", {"login": login, "password": password})
        if response.status_code != 302:
            return response
        assert submit("/login/code", {"code": last_code(outbox)}).status_code == 302
        key = key_file if key_file is not None else key_files[login.lower()]
        return submit("/login/key", {"key_file": (io.BytesIO(key), "key.json")})

    return run
