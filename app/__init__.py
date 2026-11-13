import os

from flask import Flask, render_template

from app import auth, db, reset
from app.csrf import check_csrf, csrf_token
from app.sessions import PostgresSessionInterface

PASSWORD_ITERATIONS = 1000


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config["DATABASE_URL"] = os.environ.get("DATABASE_URL")
    app.config["PASSWORD_ITERATIONS"] = PASSWORD_ITERATIONS
    app.config["SESSION_COOKIE_SECURE"] = False
    app.config["MAIL_SERVER"] = os.environ.get("MAIL_SERVER", "127.0.0.1")
    app.config["MAIL_PORT"] = int(os.environ.get("MAIL_PORT", "1025"))
    app.config["MAIL_SENDER"] = "noreply@ib.local"
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
    app.config.update(config or {})

    db.init_app(app)
    app.session_interface = PostgresSessionInterface()
    app.before_request(check_csrf)
    app.jinja_env.globals["csrf_token"] = csrf_token
    app.register_blueprint(auth.bp)
    app.register_blueprint(reset.bp)
    app.cli.add_command(auth.set_role_command)

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app
