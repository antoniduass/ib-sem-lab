import psycopg
from flask import Blueprint, current_app, redirect, render_template, request, url_for

from app import validation
from app.db import get_db
from app.passwords import hash_password

bp = Blueprint("auth", __name__)

DUPLICATE_ERRORS = {
    "users_login_key": ("login", "Этот логин уже занят."),
    "users_email_key": ("email", "Этот email уже зарегистрирован."),
}


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
