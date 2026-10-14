from app import create_app


def test_health_returns_ok():
    response = create_app().test_client().get("/health")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_database_url_is_read_from_environment(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://user@localhost/ib")

    assert create_app().config["DATABASE_URL"] == "postgresql://user@localhost/ib"
