"""Messages: encrypted with RSA-32768 or Kuznyechik, signed with the author's
GOST 34.10 key, exported to PDF and verified by anyone at /verify."""

import base64
import io
import json
import secrets
from datetime import UTC, datetime

from flask import (
    Blueprint,
    abort,
    g,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from app.auth import login_required
from app.db import get_db
from app.keystore import system_rsa_key, unwrap, wrap
from app.pdf import extract_signed_data, message_pdf
from app.signing_keys import (
    CURVE_NAME,
    decode_public_key,
    decode_signature,
    encode_signature,
)
from gostcrypto import rsa
from gostcrypto.ctr import IV_BYTES, ctr_decrypt, ctr_encrypt
from gostcrypto.gost3410 import PARAMSET_512_A, sign, verify
from gostcrypto.kuznyechik import KEY_BYTES

bp = Blueprint("messages", __name__)

ALGORITHMS = {
    "kuznyechik": "Кузнечик (ГОСТ 34.12), режим гаммирования (ГОСТ 34.13)",
    "rsa": "RSA-32768, дополнение PKCS#1 v1.5",
}
MAX_MESSAGE_BYTES = 4000


def canonical(payload: dict) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def encrypt(
    algorithm: str, plaintext: bytes
) -> tuple[bytes, bytes | None, bytes | None]:
    if algorithm == "rsa":
        return rsa.encrypt(system_rsa_key().public_key, plaintext), None, None
    key = secrets.token_bytes(KEY_BYTES)
    iv = secrets.token_bytes(IV_BYTES)
    return ctr_encrypt(key, iv, plaintext), iv, wrap(key)


def decrypt(payload: dict, wrapped_key: bytes | None) -> bytes:
    ciphertext = base64.b64decode(payload["ciphertext"])
    if payload["algorithm"] == "rsa":
        return rsa.decrypt(system_rsa_key(), ciphertext)
    return ctr_decrypt(unwrap(wrapped_key), base64.b64decode(payload["iv"]), ciphertext)


def user_signing_keys(user_id: int) -> tuple[int, bytes]:
    wrapped, public_key = (
        get_db()
        .execute(
            "SELECT signing_key_encrypted, signing_public_key FROM users WHERE id = %s",
            (user_id,),
        )
        .fetchone()
    )
    return int.from_bytes(unwrap(wrapped), "big"), public_key


def own_message(message_id: int) -> tuple:
    row = (
        get_db()
        .execute(
            "SELECT id, payload, wrapped_key, signature, signer_public_key FROM messages"
            " WHERE id = %s AND user_id = %s",
            (message_id, g.user.id),
        )
        .fetchone()
    )
    if row is None:
        abort(404)
    return row


@bp.get("/messages")
@login_required
def list_messages():
    rows = (
        get_db()
        .execute(
            "SELECT id, payload FROM messages WHERE user_id = %s ORDER BY id DESC",
            (g.user.id,),
        )
        .fetchall()
    )
    messages = [(message_id, json.loads(payload)) for message_id, payload in rows]
    return render_template("messages.html", messages=messages, algorithms=ALGORITHMS)


@bp.route("/messages/new", methods=["GET", "POST"])
@login_required
def new_message():
    text = request.form.get("text", "")
    algorithm = request.form.get("algorithm", "kuznyechik")
    error = None
    if request.method == "POST":
        plaintext = text.encode()
        if algorithm not in ALGORITHMS:
            error = "Выберите алгоритм шифрования."
        elif not text.strip() or len(plaintext) > MAX_MESSAGE_BYTES:
            error = (
                f"Сообщение должно быть непустым и не длиннее {MAX_MESSAGE_BYTES} байт."
            )
        else:
            store_message(algorithm, plaintext)
            return redirect(url_for("messages.list_messages"))
    return render_template(
        "message_new.html",
        text=text,
        algorithm=algorithm,
        error=error,
        algorithms=ALGORITHMS,
        max_bytes=MAX_MESSAGE_BYTES,
    ), (400 if error else 200)


def store_message(algorithm: str, plaintext: bytes) -> None:
    ciphertext, iv, wrapped_key = encrypt(algorithm, plaintext)
    payload = canonical(
        {
            "author": g.user.login,
            "algorithm": algorithm,
            "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "ciphertext": b64(ciphertext),
            "iv": b64(iv) if iv else None,
        }
    )
    signing_key, public_key = user_signing_keys(g.user.id)
    signature = sign(PARAMSET_512_A, signing_key, payload)
    get_db().execute(
        "INSERT INTO messages (user_id, payload, wrapped_key, signature, signer_public_key)"
        " VALUES (%s, %s, %s, %s, %s)",
        (g.user.id, payload, wrapped_key, encode_signature(signature), public_key),
    )


@bp.post("/messages/<int:message_id>/decrypt")
@login_required
def decrypt_message(message_id: int):
    _, payload, wrapped_key, _, _ = own_message(message_id)
    plaintext = decrypt(json.loads(payload), wrapped_key).decode()
    return render_template(
        "message.html",
        message_id=message_id,
        payload=json.loads(payload),
        plaintext=plaintext,
        algorithms=ALGORITHMS,
    )


@bp.get("/messages/<int:message_id>/pdf")
@login_required
def message_pdf_download(message_id: int):
    _, payload, _, signature, public_key = own_message(message_id)
    fields = json.loads(payload)
    r, s = decode_signature(signature)
    lines = [
        f"Автор: {fields['author']}",
        f"Создано (UTC): {fields['created_at']}",
        f"Шифрование: {ALGORITHMS[fields['algorithm']]}",
        "",
        "Шифртекст (base64):",
        fields["ciphertext"],
        "",
        "Электронная подпись по ГОСТ 34.10-2018, хэш — Стрибог-512,",
        f"кривая {CURVE_NAME}. Подписан JSON-блок с полями выше.",
        f"r = {r:0128x}",
        f"s = {s:0128x}",
        f"Ключ проверки подписи (x‖y): {bytes(public_key).hex()}",
        "",
        "Проверить подпись: загрузите этот файл на странице /verify.",
    ]
    signed_data = {
        "curve": CURVE_NAME,
        "payload": b64(payload),
        "signature": bytes(signature).hex(),
        "public_key": bytes(public_key).hex(),
    }
    content = message_pdf(f"Зашифрованное сообщение № {message_id}", lines, signed_data)
    return send_file(
        io.BytesIO(content),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"message-{message_id}.pdf",
    )


@bp.route("/verify", methods=["GET", "POST"])
def verify_pdf():
    result = None
    if request.method == "POST":
        uploaded = request.files.get("pdf_file")
        result = check_signed_pdf(uploaded.read() if uploaded else b"")
    return render_template("verify.html", result=result, algorithms=ALGORITHMS), (
        400 if result and not result["valid"] else 200
    )


def check_signed_pdf(pdf_bytes: bytes) -> dict:
    try:
        data = extract_signed_data(pdf_bytes)
        payload = base64.b64decode(data["payload"], validate=True)
        fields = json.loads(payload)
        public_key = bytes.fromhex(data["public_key"])
        valid = data["curve"] == CURVE_NAME and verify(
            PARAMSET_512_A,
            decode_public_key(public_key),
            payload,
            decode_signature(bytes.fromhex(data["signature"])),
        )
    except (ValueError, KeyError, TypeError):
        return {"valid": False, "fields": None, "key_status": None}
    return {
        "valid": valid,
        "fields": fields if valid else None,
        "key_status": key_status(fields.get("author"), public_key) if valid else None,
    }


def key_status(author: str | None, public_key: bytes) -> str:
    row = (
        get_db()
        .execute("SELECT signing_public_key FROM users WHERE login = %s", (author,))
        .fetchone()
    )
    if row is None:
        return "unknown"
    return "current" if bytes(row[0]) == public_key else "replaced"
