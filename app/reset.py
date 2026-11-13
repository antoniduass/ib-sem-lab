from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from app import mail, validation
from app.codes import consume_code, issue_code
from app.db import get_db
from app.passwords import hash_password
from app.recovery import consume_recovery_code, looks_like_recovery_code
from app.sessions import end_user_sessions

bp = Blueprint("reset", __name__)

MAX_ATTEMPTS = 5
CODE_REJECTED = "Неверный или просроченный код."


def find_user_id(email: str) -> int | None:
    row = (
        get_db()
        .execute("SELECT id FROM users WHERE lower(email) = lower(%s)", (email,))
        .fetchone()
    )
    return row[0] if row else None


@bp.route("/reset", methods=["GET", "POST"])
def request_reset():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        session.clear()
        session["reset_email"] = email
        session["attempts"] = 0
        user_id = find_user_id(email)
        if user_id is not None:
            code = issue_code(user_id, "reset")
            mail.send_mail(
                email,
                "Код для сброса пароля",
                f"Ваш код для сброса пароля: {code}\n"
                "Код действует 10 минут и срабатывает один раз.\n"
                "Если вы не запрашивали сброс, просто проигнорируйте это письмо.",
            )
        return redirect(url_for("reset.confirm_reset"))
    return render_template("reset.html")


@bp.route("/reset/confirm", methods=["GET", "POST"])
def confirm_reset():
    if "reset_email" not in session:
        return redirect(url_for("reset.request_reset"))
    errors = {}
    if request.method == "POST":
        password = request.form.get("password", "")
        errors = validation.validate_new_password(
            password, request.form.get("password_confirm", "")
        )
        if not errors:
            user_id = find_user_id(session["reset_email"])
            code = request.form.get("code", "").strip()
            if user_id is not None and consume_reset_code(user_id, code):
                change_password(user_id, password)
                session.clear()
                flash("Пароль изменён. Войдите с новым паролем.")
                return redirect(url_for("auth.login"))
            errors["code"] = CODE_REJECTED
            session["attempts"] += 1
            if session["attempts"] >= MAX_ATTEMPTS:
                session.clear()
                flash("Слишком много неудачных попыток. Запросите сброс заново.")
                return redirect(url_for("reset.request_reset"))
    return render_template("reset_confirm.html", errors=errors, rules=validation), (
        400 if errors else 200
    )


def consume_reset_code(user_id: int, code: str) -> bool:
    if looks_like_recovery_code(code):
        return consume_recovery_code(user_id, code)
    return consume_code(user_id, "reset", code)


def change_password(user_id: int, password: str) -> None:
    iterations = current_app.config["PASSWORD_ITERATIONS"]
    salt, password_hash = hash_password(password, iterations)
    db = get_db()
    with db.transaction():
        db.execute(
            "UPDATE users SET password_salt = %s, password_iterations = %s,"
            " password_hash = %s WHERE id = %s",
            (salt, iterations, password_hash, user_id),
        )
        end_user_sessions(user_id)
