from flask import (
    Blueprint,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)

from app.auth import role_required
from app.db import get_db
from app.sessions import end_user_sessions

bp = Blueprint("admin", __name__, url_prefix="/admin")

ROLES = ("user", "admin")
EVENT_NAMES = {
    "success": "успешный вход",
    "password_failed": "неверный логин или пароль",
    "blocked": "попытка входа заблокированного",
    "code_failed": "неверный код из письма",
    "key_failed": "неверный файл ключа или код восстановления",
}
LOG_LIMIT = 200


@bp.get("")
@role_required("admin")
def users():
    rows = (
        get_db()
        .execute("SELECT id, login, email, role, is_blocked FROM users ORDER BY id")
        .fetchall()
    )
    return render_template("admin.html", users=rows, roles=ROLES)


@bp.get("/log")
@role_required("admin")
def login_log():
    events = (
        get_db()
        .execute(
            "SELECT created_at AT TIME ZONE 'UTC', login, event, ip_address"
            " FROM login_events"
            " ORDER BY id DESC LIMIT %s",
            (LOG_LIMIT,),
        )
        .fetchall()
    )
    return render_template("admin_log.html", events=events, event_names=EVENT_NAMES)


def target_user(user_id: int) -> int | None:
    if user_id == g.user.id:
        flash("Нельзя менять роль или блокировать собственную учётную запись.")
        return None
    row = get_db().execute("SELECT id FROM users WHERE id = %s", (user_id,)).fetchone()
    if row is None:
        abort(404)
    return user_id


@bp.post("/users/<int:user_id>/role")
@role_required("admin")
def change_role(user_id: int):
    role = request.form.get("role")
    if role not in ROLES:
        abort(400)
    if target_user(user_id) is not None:
        get_db().execute("UPDATE users SET role = %s WHERE id = %s", (role, user_id))
    return redirect(url_for("admin.users"))


@bp.post("/users/<int:user_id>/block")
@role_required("admin")
def block(user_id: int):
    if target_user(user_id) is not None:
        db = get_db()
        with db.transaction():
            db.execute("UPDATE users SET is_blocked = true WHERE id = %s", (user_id,))
            end_user_sessions(user_id)
    return redirect(url_for("admin.users"))


@bp.post("/users/<int:user_id>/unblock")
@role_required("admin")
def unblock(user_id: int):
    if target_user(user_id) is not None:
        get_db().execute(
            "UPDATE users SET is_blocked = false WHERE id = %s", (user_id,)
        )
    return redirect(url_for("admin.users"))
