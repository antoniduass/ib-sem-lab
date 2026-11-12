import re

import pytest

from app.validation import (
    EMAIL_PATTERN,
    LOGIN_PATTERN,
    PASSWORD_PATTERN,
    validate_registration,
)

GOOD_PASSWORD = "Str0ng!Passw0rd"


@pytest.mark.parametrize("login", ["abc", "anton_b", "User2026", "a" * 32, "a_1"])
def test_valid_logins(login):
    assert re.fullmatch(LOGIN_PATTERN, login)


@pytest.mark.parametrize(
    "login",
    ["", "ab", "a" * 33, "1abc", "_abc", "ab-c", "ab c", "антон", "abc!", "abc\n"],
)
def test_invalid_logins(login):
    assert not re.fullmatch(LOGIN_PATTERN, login)


@pytest.mark.parametrize(
    "email",
    ["user@example.com", "first.last+tag@mail.example.ru", "a_b%c-d@sub-domain.org"],
)
def test_valid_emails(email):
    assert re.fullmatch(EMAIL_PATTERN, email)


@pytest.mark.parametrize(
    "email",
    [
        "",
        "user",
        "user@",
        "@example.com",
        "user@example",
        "user@example.c",
        "user@@example.com",
        "user name@example.com",
        "user@exa mple.com",
        "user@example.com\n",
        "пользователь@example.com",
    ],
)
def test_invalid_emails(email):
    assert not re.fullmatch(EMAIL_PATTERN, email)


@pytest.mark.parametrize(
    "password",
    [GOOD_PASSWORD, "Aa1!" * 3, "Пароль-Abc123", "A1!" + "a" * 61],
)
def test_valid_passwords(password):
    assert re.fullmatch(PASSWORD_PATTERN, password)


@pytest.mark.parametrize(
    "password",
    [
        "",
        "Aa1!" * 2 + "Aa1",
        "A1!" + "a" * 62,
        "str0ng!passw0rd",
        "STR0NG!PASSW0RD",
        "Strong!Password",
        "Str0ngPassw0rd1",
        "Str0ng!Pass\nw0rd",
    ],
)
def test_invalid_passwords(password):
    assert not re.fullmatch(PASSWORD_PATTERN, password)


def test_validate_registration_accepts_good_form():
    assert (
        validate_registration("anton", "a@example.com", GOOD_PASSWORD, GOOD_PASSWORD)
        == {}
    )


def test_validate_registration_reports_every_field():
    errors = validate_registration("1", "bad", "weak", "other")
    assert set(errors) == {"login", "email", "password", "password_confirm"}


def test_validate_registration_rejects_too_long_email():
    email = "a" * 250 + "@example.com"
    assert re.fullmatch(EMAIL_PATTERN, email)
    assert "email" in validate_registration(
        "anton", email, GOOD_PASSWORD, GOOD_PASSWORD
    )
