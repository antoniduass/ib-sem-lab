import secrets

from flask import abort, request, session


def csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def check_csrf() -> None:
    if request.method != "POST":
        return
    expected = session.get("csrf_token")
    sent = request.form.get("csrf_token", "")
    if not expected or not secrets.compare_digest(expected, sent):
        abort(400, "CSRF token is missing or invalid.")
