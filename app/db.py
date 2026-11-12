from pathlib import Path

import click
import psycopg
from flask import Flask, current_app, g
from flask.cli import with_appcontext

SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def get_db() -> psycopg.Connection:
    if "db" not in g:
        g.db = psycopg.connect(current_app.config["DATABASE_URL"], autocommit=True)
    return g.db


def close_db(_error: BaseException | None = None) -> None:
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def init_db() -> None:
    get_db().execute(SCHEMA_PATH.read_text())


@click.command("init-db")
@with_appcontext
def init_db_command() -> None:
    init_db()
    click.echo("Database schema is up to date.")


def init_app(app: Flask) -> None:
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
