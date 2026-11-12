import os

import pytest

from app import create_app
from app.db import get_db, init_db

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
        get_db().execute("TRUNCATE users RESTART IDENTITY")
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
