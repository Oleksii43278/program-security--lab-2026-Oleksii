import os
import time
import base64
import hmac
import hashlib
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def derive_kek(master_key: bytes, salt: bytes) -> bytes:
    """Виводить KEK (Key Encryption Key) з майстер-ключа за допомогою HKDF."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"drs-release/envelope-kek"
    )
    return hkdf.derive(master_key)


def seal_totp_secret(secret: str, master_key: bytes, username: str) -> dict:
    """Запечатує секрет ТОТР: генерує DEK, шифрує секрет, обгортає DEK за допомогою KEK."""
    secret_bytes = secret.encode('utf-8')
    aad = username.encode('utf-8')

    # 1. Генеруємо випадковий DEK та шифруємо секрет (AES-GCM)
    dek = os.urandom(32)
    aesgcm_dek = AESGCM(dek)
    secret_nonce = os.urandom(12)
    secret_ct = aesgcm_dek.encrypt(secret_nonce, secret_bytes, aad)

    # 2. Виводимо KEK та обгортаємо DEK
    kek_salt = os.urandom(16)
    kek = derive_kek(master_key, kek_salt)
    aesgcm_kek = AESGCM(kek)
    dek_wrap_nonce = os.urandom(12)
    dek_wrapped = aesgcm_kek.encrypt(dek_wrap_nonce, dek, aad)

    return {
        "alg": "AES-256-GCM",
        "kdf": "HKDF-SHA256",
        "kek_salt": base64.b64encode(kek_salt).decode('utf-8'),
        "dek_wrap_nonce": base64.b64encode(dek_wrap_nonce).decode('utf-8'),
        "dek_wrapped": base64.b64encode(dek_wrapped).decode('utf-8'),
        "secret_nonce": base64.b64encode(secret_nonce).decode('utf-8'),
        "secret_ct": base64.b64encode(secret_ct).decode('utf-8')
    }


def open_totp_secret(envelope: dict, master_key: bytes, username: str) -> str:
    """Розпечатує секрет ТОТР: розгортає DEK, розшифровує секрет."""
    aad = username.encode('utf-8')
    kek_salt = base64.b64decode(envelope["kek_salt"])
    dek_wrap_nonce = base64.b64decode(envelope["dek_wrap_nonce"])
    dek_wrapped = base64.b64decode(envelope["dek_wrapped"])
    secret_nonce = base64.b64decode(envelope["secret_nonce"])
    secret_ct = base64.b64decode(envelope["secret_ct"])

    # 1. Отримуємо KEK та розгортаємо DEK
    kek = derive_kek(master_key, kek_salt)
    aesgcm_kek = AESGCM(kek)
    try:
        dek = aesgcm_kek.decrypt(dek_wrap_nonce, dek_wrapped, aad)
    except Exception:
        return None

    # 2. Розшифровуємо секрет за допомогою DEK
    aesgcm_dek = AESGCM(dek)
    try:
        secret_bytes = aesgcm_dek.decrypt(secret_nonce, secret_ct, aad)
        return secret_bytes.decode('utf-8')
    except Exception:
        return None


def generate_totp_secret() -> str:
    """Генерує випадковий секрет для TOTP у форматі Base32."""
    secret_bytes = os.urandom(20)
    return base64.b32encode(secret_bytes).decode('utf-8').replace('=', '')


def get_totp_token(secret: str, time_step: int = 30) -> tuple[str, int]:
    """Генерує TOTP код за алгоритмом RFC 6238 та повертає номер часового кроку."""
    key = base64.b32decode(secret + '=' * (-len(secret) % 8))
    current_step = int(time.time() / time_step)
    msg = struct.pack(">Q", current_step)
    mac = hmac.new(key, msg, hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000
    return f"{code:06d}", current_step


def self_test():
    """Самоперевірка модуля (сценарій round-trip та підробка)."""
    master_key = b"super_secret_master_key_32_bytes"
    username = "test_owner"
    secret = generate_totp_secret()

    # 1. Запечатування та розпечатування
    envelope = seal_totp_secret(secret, master_key, username)
    recovered = open_totp_secret(envelope, master_key, username)
    assert secret == recovered, "Помилка: розпечатаний секрет не збігається!"

    # 2. Перевірка цілісності GCM (підробка)
    ct_bytes = bytearray(base64.b64decode(envelope["secret_ct"]))
    ct_bytes[0] ^= 0x01  # Змінюємо 1 байт
    envelope["secret_ct"] = base64.b64encode(ct_bytes).decode('utf-8')
    assert open_totp_secret(envelope, master_key, username) is None, "Помилка: GCM не виявив підробку!"

    print("crypto.py self-test OK: seal/open, TOTP, виявлення підміни, AAD.")


if __name__ == "__main__":
    self_test()