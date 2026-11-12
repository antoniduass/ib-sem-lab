import os

from flask import Flask, render_template

from app import auth, db

PASSWORD_ITERATIONS = 1000


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config["DATABASE_URL"] = os.environ.get("DATABASE_URL")
    app.config["PASSWORD_ITERATIONS"] = PASSWORD_ITERATIONS
    app.config.update(config or {})

    db.init_app(app)
    app.register_blueprint(auth.bp)

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app
