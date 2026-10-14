import os

from flask import Flask


def create_app():
    app = Flask(__name__)
    app.config["DATABASE_URL"] = os.environ.get("DATABASE_URL")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app
