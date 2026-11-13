"""Server-side sessions (D-007): the cookie holds a random token, PostgreSQL holds
the session data under the Streebog-512 hash of that token."""

import secrets
from datetime import timedelta

from flask import Flask, Request, Response
from flask.sessions import SessionInterface, SessionMixin
from psycopg.types.json import Jsonb
from werkzeug.datastructures import CallbackDict

from app.db import get_db
from gostcrypto.streebog import streebog512

COOKIE_NAME = "session_id"
LIFETIME = timedelta(hours=1)


class ServerSession(CallbackDict, SessionMixin):
    def __init__(self, data: dict | None = None, token: str | None = None):
        def on_update(session):
            session.modified = True

        super().__init__(data, on_update)
        self.token = token
        self.rotate = False
        self.modified = False

    def regenerate(self) -> None:
        self.rotate = True
        self.modified = True


def token_hash(token: str) -> bytes:
    return streebog512(token.encode())


class PostgresSessionInterface(SessionInterface):
    def open_session(self, app: Flask, request: Request) -> ServerSession:
        token = request.cookies.get(COOKIE_NAME)
        if token:
            row = (
                get_db()
                .execute(
                    "SELECT data FROM sessions WHERE token_hash = %s AND expires_at > now()",
                    (token_hash(token),),
                )
                .fetchone()
            )
            if row is not None:
                return ServerSession(row[0], token)
        return ServerSession()

    def save_session(
        self, app: Flask, session: ServerSession, response: Response
    ) -> None:
        if session.token and (session.rotate or not session):
            get_db().execute(
                "DELETE FROM sessions WHERE token_hash = %s",
                (token_hash(session.token),),
            )
            if not session:
                response.delete_cookie(COOKIE_NAME)
                return
            session.token = None
        if not session:
            return
        if session.token is None:
            session.token = secrets.token_urlsafe(32)
            get_db().execute("DELETE FROM sessions WHERE expires_at <= now()")
        get_db().execute(
            "INSERT INTO sessions (token_hash, data, expires_at) VALUES (%s, %s, now() + %s)"
            " ON CONFLICT (token_hash) DO UPDATE"
            " SET data = EXCLUDED.data, expires_at = EXCLUDED.expires_at",
            (token_hash(session.token), Jsonb(dict(session)), LIFETIME),
        )
        response.set_cookie(
            COOKIE_NAME,
            session.token,
            max_age=LIFETIME,
            httponly=True,
            samesite="Lax",
            secure=app.config["SESSION_COOKIE_SECURE"],
        )


def end_user_sessions(user_id: int) -> None:
    get_db().execute(
        "DELETE FROM sessions WHERE data->>'user_id' = %s OR data->>'pending_user_id' = %s",
        (str(user_id), str(user_id)),
    )
