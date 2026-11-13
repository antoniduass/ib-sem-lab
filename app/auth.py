import base64
import secrets
from functools import wraps

import click
import psycopg
from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask.cli import with_appcontext
from psycopg.rows import namedtuple_row

from app import mail, validation
from app.codes import consume_code, issue_code
from app.db import get_db
from app.keystore import wrap
from app.passwords import SALT_BYTES, hash_password, verify_password
from app.recovery import (
    consume_recovery_code,
    issue_recovery_codes,
    looks_like_recovery_code,
    remaining_recovery_codes,
)
from app.signing_keys import (
    decode_public_key,
    encode_public_key,
    key_file,
    read_key_file,
)
from gostcrypto.gost3410 import PARAMSET_512_A, generate_keys, sign, verify

bp = Blueprint("auth", __name__)

DUPLICATE_ERRORS = {
    "users_login_key": ("login", "Этот логин уже занят."),
    "users_email_key": ("email", "Этот email уже зарегистрирован."),
}
LOGIN_FAILED = "Неверный логин или пароль."
ACCOUNT_BLOCKED = "Учётная запись заблокирована администратором."
MAX_ATTEMPTS = 5
TOO_MANY_ATTEMPTS = "Слишком много неудачных попыток. Войдите заново."
KEY_REJECTED = "Файл ключа не подходит."
KEY_REISSUE_HINT = (
    "Вы вошли по коду восстановления. Выпустите новый файл ключа ЭЦП в кабинете."
)
TIMING_DUMMY_SALT = bytes(SALT_BYTES)


@bp.before_app_request
def load_user() -> None:
    user_id = session.get("user_id")
    g.user = None
    if user_id is not None:
        g.user = (
            get_db()
            .cursor(row_factory=namedtuple_row)
            .execute(
                "SELECT id, login, role FROM users WHERE id = %s AND NOT is_blocked",
                (user_id,),
            )
            .fetchone()
        )
        if g.user is None:
            session.clear()


def log_login_event(user_id: int | None, login: str | None, event: str) -> None:
    get_db().execute(
        "INSERT INTO login_events (user_id, login, event, ip_address) VALUES"
        " (%s, COALESCE(%s, (SELECT login FROM users WHERE id = %s)), %s, %s)",
        (user_id, login, user_id, event, request.remote_addr),
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
            errors, user_id, signing_key = create_user(login, email, password)
        if not errors:
            return render_template(
                "registered.html",
                login=login,
                key_file_base64=key_file_base64(login, signing_key),
                recovery_codes=issue_recovery_codes(user_id),
            )
    return render_template(
        "register.html", login=login, email=email, errors=errors, rules=validation
    ), (400 if errors else 200)


def wrap_signing_key(signing_key: int) -> bytes:
    return wrap(signing_key.to_bytes(64, "big"))


def key_file_base64(login: str, signing_key: int) -> str:
    return base64.b64encode(key_file(login, signing_key)).decode()


def create_user(
    login: str, email: str, password: str
) -> tuple[dict[str, str], int | None, int | None]:
    iterations = current_app.config["PASSWORD_ITERATIONS"]
    salt, password_hash = hash_password(password, iterations)
    signing_key, public_key = generate_keys(PARAMSET_512_A)
    try:
        (user_id,) = (
            get_db()
            .execute(
                "INSERT INTO users (login, email, password_salt, password_iterations,"
                " password_hash, signing_public_key, signing_key_encrypted)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
                (
                    login,
                    email,
                    salt,
                    iterations,
                    password_hash,
                    encode_public_key(public_key),
                    wrap_signing_key(signing_key),
                ),
            )
            .fetchone()
        )
    except psycopg.errors.UniqueViolation as error:
        field, message = DUPLICATE_ERRORS[error.diag.constraint_name]
        return {field: message}, None, None
    return {}, user_id, signing_key


@bp.route("/login", methods=["GET", "POST"])
def login():
    login = request.form.get("login", "").strip()
    error = None
    if request.method == "POST":
        user_id = authenticate(login, request.form.get("password", ""))
        if user_id is None:
            log_login_event(None, login, "password_failed")
            error = LOGIN_FAILED
        elif is_blocked(user_id):
            log_login_event(user_id, None, "blocked")
            error = ACCOUNT_BLOCKED
        else:
            session.clear()
            session.regenerate()
            session["pending_user_id"] = user_id
            session["login_step"] = 2
            session["attempts"] = 0
            send_login_code(user_id)
            return redirect(url_for("auth.login_code"))
    return render_template("login.html", login=login, error=error), (
        400 if error else 200
    )


def is_blocked(user_id: int) -> bool:
    (blocked,) = (
        get_db()
        .execute("SELECT is_blocked FROM users WHERE id = %s", (user_id,))
        .fetchone()
    )
    return blocked


def send_login_code(user_id: int) -> None:
    (email,) = (
        get_db().execute("SELECT email FROM users WHERE id = %s", (user_id,)).fetchone()
    )
    code = issue_code(user_id, "login")
    mail.send_mail(
        email,
        "Код для входа",
        f"Ваш код для входа: {code}\nКод действует 10 минут и срабатывает один раз.",
    )


def login_step_required(step: int):
    def decorator(view):
        @wraps(view)
        def wrapped(**kwargs):
            if session.get("login_step") != step:
                return redirect(url_for("auth.login"))
            return view(**kwargs)

        return wrapped

    return decorator


def count_failed_attempt():
    session["attempts"] += 1
    if session["attempts"] < MAX_ATTEMPTS:
        return None
    session.clear()
    flash(TOO_MANY_ATTEMPTS)
    return redirect(url_for("auth.login"))


@bp.route("/login/code", methods=["GET", "POST"])
@login_step_required(2)
def login_code():
    error = None
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if consume_login_code(session["pending_user_id"], code):
            session["login_step"] = 3
            session["attempts"] = 0
            session["challenge"] = secrets.token_hex(32)
            return redirect(url_for("auth.login_key"))
        error = "Неверный или просроченный код."
        log_login_event(session["pending_user_id"], None, "code_failed")
        if (restart := count_failed_attempt()) is not None:
            return restart
    return render_template("login_code.html", error=error), (400 if error else 200)


def consume_login_code(user_id: int, code: str) -> bool:
    if looks_like_recovery_code(code):
        session["recovery_used"] = consume_recovery_code(user_id, code)
        return session["recovery_used"]
    return consume_code(user_id, "login", code)


@bp.route("/login/key", methods=["GET", "POST"])
@login_step_required(3)
def login_key():
    error = None
    if request.method == "POST":
        uploaded = request.files.get("key_file")
        recovery_code = request.form.get("recovery_code", "").strip()
        if recovery_code:
            accepted = not session.get("recovery_used") and consume_recovery_code(
                session["pending_user_id"], recovery_code
            )
        else:
            accepted = uploaded is not None and key_matches(uploaded.read())
        if accepted:
            user_id = session["pending_user_id"]
            session.clear()
            session.regenerate()
            session["user_id"] = user_id
            log_login_event(user_id, None, "success")
            if recovery_code:
                flash(KEY_REISSUE_HINT)
            return redirect(url_for("auth.account"))
        error = "Код восстановления не подходит." if recovery_code else KEY_REJECTED
        log_login_event(session["pending_user_id"], None, "key_failed")
        if (restart := count_failed_attempt()) is not None:
            return restart
    return render_template(
        "login_key.html", error=error, recovery_allowed=not session.get("recovery_used")
    ), (400 if error else 200)


def key_matches(file_content: bytes) -> bool:
    try:
        signing_key = read_key_file(file_content)
    except ValueError:
        return False
    (public_key,) = (
        get_db()
        .execute(
            "SELECT signing_public_key FROM users WHERE id = %s",
            (session["pending_user_id"],),
        )
        .fetchone()
    )
    challenge = session["challenge"].encode()
    signature = sign(PARAMSET_512_A, signing_key, challenge)
    return verify(PARAMSET_512_A, decode_public_key(public_key), challenge, signature)


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
    return render_template(
        "account.html", recovery_codes_left=remaining_recovery_codes(g.user.id)
    )


@bp.post("/account/recovery-codes")
@login_required
def new_recovery_codes():
    return render_template(
        "recovery_codes.html", recovery_codes=issue_recovery_codes(g.user.id)
    )


@bp.post("/account/signing-key")
@login_required
def new_signing_key():
    signing_key, public_key = generate_keys(PARAMSET_512_A)
    get_db().execute(
        "UPDATE users SET signing_public_key = %s, signing_key_encrypted = %s"
        " WHERE id = %s",
        (encode_public_key(public_key), wrap_signing_key(signing_key), g.user.id),
    )
    return render_template(
        "signing_key.html", key_file_base64=key_file_base64(g.user.login, signing_key)
    )


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
