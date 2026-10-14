# ib-sem-lab

Учебное веб-приложение по информационной безопасности. Требования — `assignment/SPEC.md`.

## Требования

- Python 3.13
- [uv](https://docs.astral.sh/uv/)
- PostgreSQL

## Установка

```bash
uv sync
cp .env.example .env
```

В `.env` укажите строку подключения к PostgreSQL в `DATABASE_URL`.

## Запуск

```bash
set -a; source .env; set +a
uv run flask --app app run
```

Проверка: `http://127.0.0.1:5000/health` возвращает `{"status": "ok"}`.

## Тесты и проверки

```bash
uv run pytest
uv run ruff check
uv run ruff format --check
```
