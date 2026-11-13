"""Separate demonstration of Streebog, Kuznyechik and RSA (SPEC ТП-18).
Forms are prefilled with the examples of the standards so results can be compared."""

import time

from flask import Blueprint, render_template, request

from app.keystore import demo_rsa_key, system_rsa_key
from gostcrypto import rsa
from gostcrypto.ctr import IV_BYTES, ctr_decrypt, ctr_encrypt
from gostcrypto.kuznyechik import KEY_BYTES
from gostcrypto.streebog import streebog512

bp = Blueprint("demo", __name__)

# GOST 34.11-2018, appendix A, example 1 (message M1)
STREEBOG_EXAMPLE = "012345678901234567890123456789012345678901234567890123456789012"
# GOST 34.13-2018, appendix A.2.3: key, IV and plaintext of the counter mode example
KUZNYECHIK_EXAMPLE = {
    "key": "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
    "iv": "1234567890abcef0",
    "plaintext": "1122334455667700ffeeddccbbaa9988"
    "00112233445566778899aabbcceeff0a"
    "112233445566778899aabbcceeff0a00"
    "2233445566778899aabbcceeff0a0011",
}
RSA_KEYS = {"demo": "демонстрационный, 2048 бит", "system": "системный, 32768 бит"}


@bp.route("/demo", methods=["GET", "POST"])
def demo():
    form = {
        "text": STREEBOG_EXAMPLE,
        **KUZNYECHIK_EXAMPLE,
        "rsa_text": "Привет, RSA!",
        "rsa_key": "demo",
    }
    form.update(request.form.to_dict())
    results = {}
    error = None
    action = request.form.get("action")
    try:
        if action == "streebog":
            results["streebog"] = run_streebog(form["text"])
        elif action == "kuznyechik":
            results["kuznyechik"] = run_kuznyechik(
                form["key"], form["iv"], form["plaintext"]
            )
        elif action == "rsa":
            results["rsa"] = run_rsa(form["rsa_text"], form["rsa_key"])
    except ValueError as problem:
        error = str(problem)
    return render_template(
        "demo.html", form=form, results=results, error=error, rsa_keys=RSA_KEYS
    ), (400 if error else 200)


def run_streebog(text: str) -> dict:
    digest = streebog512(text.encode())
    return {"bytes": digest.hex(), "standard": digest[::-1].hex()}


def parse_hex(value: str, name: str, length: int | None = None) -> bytes:
    try:
        data = bytes.fromhex(value.strip())
    except ValueError:
        raise ValueError(f"{name}: нужна строка из шестнадцатеричных цифр.") from None
    if length is not None and len(data) != length:
        raise ValueError(f"{name}: нужно ровно {length} байт ({2 * length} hex-цифр).")
    return data


def run_kuznyechik(key_hex: str, iv_hex: str, plaintext_hex: str) -> dict:
    key = parse_hex(key_hex, "Ключ", KEY_BYTES)
    iv = parse_hex(iv_hex, "Синхропосылка", IV_BYTES)
    plaintext = parse_hex(plaintext_hex, "Открытый текст")
    ciphertext = ctr_encrypt(key, iv, plaintext)
    return {
        "ciphertext": ciphertext.hex(),
        "decrypted": ctr_decrypt(key, iv, ciphertext).hex(),
    }


def run_rsa(text: str, key_name: str) -> dict:
    if key_name not in RSA_KEYS:
        raise ValueError("Выберите ключ RSA.")
    key = demo_rsa_key() if key_name == "demo" else system_rsa_key()
    started = time.perf_counter()
    ciphertext = rsa.encrypt(key.public_key, text.encode())
    encrypted_at = time.perf_counter()
    decrypted = rsa.decrypt(key, ciphertext).decode()
    finished = time.perf_counter()
    return {
        "modulus_bits": key.n.bit_length(),
        "ciphertext": ciphertext.hex(),
        "decrypted": decrypted,
        "encrypt_seconds": encrypted_at - started,
        "decrypt_seconds": finished - encrypted_at,
    }
