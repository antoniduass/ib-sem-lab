from functools import wraps

import click
import psycopg
from flask import (
    Blueprint,
    abort,
    current_app,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask.cli import with_appcontext
from psycopg.rows import namedtuple_row

from app import validation
from app.db import get_db
from app.passwords import SALT_BYTES, hash_password, verify_password

bp = Blueprint("auth", __name__)

DUPLICATE_ERRORS = {
    "users_login_key": ("login", "Этот логин уже занят."),
    "users_email_key": ("email", "Этот email уже зарегистрирован."),
}
LOGIN_FAILED = "Неверный логин или пароль."
TIMING_DUMMY_SALT = bytes(SALT_BYTES)


@bp.before_app_request
def load_user() -> None:
    user_id = session.get("user_id")
    g.user = None
    if user_id is not None:
        g.user = (
            get_db()
            .cursor(row_factory=namedtuple_row)
            .execute("SELECT id, login, role FROM users WHERE id = %s", (user_id,))
            .fetchone()
        )


def login_required(view):
    @wraps(view)
    def wrapped(**kwargs):
        if g.user is None:
            return redirect(url_for("auth.login"))
        return view(**kwargs)

    return wrapped


def role_required(role: str):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(**kwargs):
            if g.user.role != role:
                abort(403)
            return view(**kwargs)

        return wrapped

    return decorator


@bp.route("/register", methods=["GET", "POST"])
def register():
    login = request.form.get("login", "").strip()
    email = request.form.get("email", "").strip()
    errors = {}
    if request.method == "POST":
        password = request.form.get("password", "")
        errors = validation.validate_registration(
            login, email, password, request.form.get("password_confirm", "")
        )
        if not errors:
            errors = create_user(login, email, password)
        if not errors:
            return redirect(url_for("auth.registered"))
    return render_template(
        "register.html", login=login, email=email, errors=errors, rules=validation
    ), (400 if errors else 200)


@bp.get("/register/done")
def registered():
    return render_template("registered.html")


def create_user(login: str, email: str, password: str) -> dict[str, str]:
    iterations = current_app.config["PASSWORD_ITERATIONS"]
    salt, password_hash = hash_password(password, iterations)
    try:
        get_db().execute(
            "INSERT INTO users (login, email, password_salt, password_iterations, password_hash)"
            " VALUES (%s, %s, %s, %s, %s)",
            (login, email, salt, iterations, password_hash),
        )
    except psycopg.errors.UniqueViolation as error:
        field, message = DUPLICATE_ERRORS[error.diag.constraint_name]
        return {field: message}
    return {}


@bp.route("/login", methods=["GET", "POST"])
def login():
    login = request.form.get("login", "").strip()
    error = None
    if request.method == "POST":
        user_id = authenticate(login, request.form.get("password", ""))
        if user_id is None:
            error = LOGIN_FAILED
        else:
            session.clear()
            session.regenerate()
            session["user_id"] = user_id
            return redirect(url_for("auth.account"))
    return render_template("login.html", login=login, error=error), (
        400 if error else 200
    )


def authenticate(login: str, password: str) -> int | None:
    row = (
        get_db()
        .execute(
            "SELECT id, password_salt, password_iterations, password_hash"
            " FROM users WHERE lower(login) = lower(%s)",
            (login,),
        )
        .fetchone()
    )
    if row is None:
        verify_password(
            password,
            TIMING_DUMMY_SALT,
            current_app.config["PASSWORD_ITERATIONS"],
            b"",
        )
        return None
    user_id, salt, iterations, password_hash = row
    return (
        user_id if verify_password(password, salt, iterations, password_hash) else None
    )


@bp.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@bp.get("/account")
@login_required
def account():
    return render_template("account.html")


@bp.get("/admin")
@role_required("admin")
def admin():
    users = (
        get_db().execute("SELECT login, email, role FROM users ORDER BY id").fetchall()
    )
    return render_template("admin.html", users=users)


@click.command("set-role")
@click.argument("login")
@click.argument("role", type=click.Choice(["user", "admin"]))
@with_appcontext
def set_role_command(login: str, role: str) -> None:
    updated = get_db().execute(
        "UPDATE users SET role = %s WHERE lower(login) = lower(%s)", (role, login)
    )
    if updated.rowcount == 0:
        raise click.ClickException(f"User {login!r} not found.")
    click.echo(f"{login}: role set to {role}.")
