"""Registration field rules. The same patterns go to the HTML `pattern` attributes.

Patterns are written so that they mean the same in Python `re` and in browser
regular expressions (HTML uses the `v` flag, which requires `\\-` inside classes).
"""

import re

LOGIN_PATTERN = r"[A-Za-z][A-Za-z0-9_]{2,31}"
EMAIL_PATTERN = r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}"
PASSWORD_PATTERN = r"(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9]).{12,64}"
EMAIL_MAX_LENGTH = 254

LOGIN_RULE = "3–32 символа: латинские буквы, цифры и _, первый символ — буква."
EMAIL_RULE = "Адрес вида name@example.com."
PASSWORD_RULE = (
    "12–64 символа: строчная и заглавная латинские буквы, цифра и спецсимвол."
)


def validate_registration(
    login: str, email: str, password: str, password_confirm: str
) -> dict[str, str]:
    errors = {}
    if not re.fullmatch(LOGIN_PATTERN, login):
        errors["login"] = LOGIN_RULE
    if len(email) > EMAIL_MAX_LENGTH or not re.fullmatch(EMAIL_PATTERN, email):
        errors["email"] = EMAIL_RULE
    if not re.fullmatch(PASSWORD_PATTERN, password):
        errors["password"] = PASSWORD_RULE
    if password != password_confirm:
        errors["password_confirm"] = "Пароли не совпадают."
    return errors
