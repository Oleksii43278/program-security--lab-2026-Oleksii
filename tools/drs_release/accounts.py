import json
import os
import secrets
import hashlib
import hmac
import time
import sys
from datetime import datetime
from crypto import derive_kek, seal_totp_secret, open_totp_secret

ACCOUNTS_FILE = "drs_release.accounts.json"
KEY_FILE = "drs_release.accounts.json.key"
AUDIT_LOG = "drs_release.audit.log"
KDF_NAME = "pbkdf2_hmac_sha256"
ITERATIONS = 600000
SALT_BYTES = 16


def write_audit(action, user=""):
    timestamp = datetime.now().isoformat(timespec='seconds')
    log_entry = f"{timestamp}\t{action}\t{user}\n"
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(log_entry)


def get_or_create_mac_key():
    """Отримує або генерує ключ HMAC для захисту бази даних."""
    if not os.path.exists(KEY_FILE):
        key = os.urandom(32)
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        write_audit("integrity-key-created")
        return key
    with open(KEY_FILE, "rb") as f:
        return f.read()


def calculate_file_mac(data_dict, key):
    """Обчислює HMAC-SHA256 для вмісту JSON (без поля mac)."""
    data_copy = data_dict.copy()
    data_copy.pop("mac", None)
    # Детермінована серіалізація JSON (щоб ключі йшли за алфавітом, без зайвих пробілів)
    dumped = json.dumps(data_copy, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hmac.new(key, dumped, hashlib.sha256).hexdigest()


def init_accounts_file():
    if not os.path.exists(ACCOUNTS_FILE):
        get_or_create_mac_key()  # Ініціалізуємо HMAC-ключ
        data = {
            "version": 1,
            "kdf": {
                "name": KDF_NAME,
                "iterations": ITERATIONS,
                "salt_bytes": SALT_BYTES
            },
            "users": {}
        }
        save_accounts(data)
        write_audit("init")
        print(f"Створено порожній файл облікових записів: {ACCOUNTS_FILE}")
        return True
    return False


def load_accounts():
    """Завантажує базу та перевіряє її цілісність через HMAC."""
    if not os.path.exists(KEY_FILE) or not os.path.exists(ACCOUNTS_FILE):
        write_audit("integrity-fail:missing")
        print("Помилка цілісності: відсутній файл бази або ключ HMAC.")
        sys.exit(2)

    with open(ACCOUNTS_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    key = get_or_create_mac_key()
    expected_mac = data.get("mac")

    if not expected_mac:
        write_audit("integrity-fail:missing")
        print("Помилка цілісності: відсутня мітка HMAC у базі.")
        sys.exit(2)

    actual_mac = calculate_file_mac(data, key)
    if not hmac.compare_digest(expected_mac, actual_mac):
        write_audit("integrity-fail:mac")
        print("Помилка цілісності: недійсний HMAC бази даних (можлива підміна)!")
        sys.exit(2)

    return data


def save_accounts(data):
    """Зберігає базу, попередньо обчисливши нову мітку HMAC."""
    key = get_or_create_mac_key()
    data["mac"] = calculate_file_mac(data, key)

    tmp_file = ACCOUNTS_FILE + ".tmp"
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    os.replace(tmp_file, ACCOUNTS_FILE)


def derive_master_key(password, salt_hex):
    salt = bytes.fromhex(salt_hex)
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, ITERATIONS)


def calculate_verifier(master_key):
    return hmac.new(master_key, b"drs-release/verifier", hashlib.sha256).hexdigest()


def add_user(username, password, role="viewer"):
    if not os.path.exists(ACCOUNTS_FILE):
        print("Помилка: Файл облікових записів не знайдено.")
        return False
    data = load_accounts()
    if username in data["users"]:
        print(f"Помилка: Користувач {username} вже існує.")
        return False
    salt = secrets.token_hex(SALT_BYTES)
    master_key = derive_master_key(password, salt)
    verifier = calculate_verifier(master_key)
    data["users"][username] = {
        "salt": salt,
        "verifier": verifier,
        "roles": [role],
        "created": datetime.now().isoformat(timespec='seconds'),
        "failed_count": 0,
        "lock_level": 0,
        "locked_until": 0,
        "totp": None,
        "totp_last_counter": None
    }
    save_accounts(data)
    write_audit("add-user", username)
    print(f"Додано користувача {username} (роль: {role}).")
    return True


def get_users_list():
    if not os.path.exists(ACCOUNTS_FILE):
        return {}
    data = load_accounts()
    return {u: d["roles"] for u, d in data["users"].items()}


def count_owners(data):
    return sum(1 for u in data["users"].values() if "owner" in u["roles"])


def set_user_role(target_user, new_role):
    data = load_accounts()
    if target_user not in data["users"]:
        print("Користувача не знайдено.")
        return False
    old_roles = data["users"][target_user]["roles"]
    if "owner" in old_roles and new_role != "owner":
        if count_owners(data) <= 1:
            print("Не можна позбавити ролі owner останнього власника.")
            return False
    data["users"][target_user]["roles"] = [new_role]
    save_accounts(data)
    write_audit("set-role", target_user)
    print(f"Роль для {target_user} змінено на {new_role}.")
    return True


def save_totp_envelope(username, envelope, step):
    data = load_accounts()
    data["users"][username]["totp"] = envelope
    data["users"][username]["totp_last_counter"] = step
    save_accounts(data)


def get_totp_envelope(username):
    data = load_accounts()
    return data["users"].get(username, {}).get("totp")


def check_totp_replay(username, current_step):
    data = load_accounts()
    last = data["users"][username].get("totp_last_counter")
    if last is not None and current_step <= last:
        return False
    data["users"][username]["totp_last_counter"] = current_step
    save_accounts(data)
    return True


def change_password(target_user, current_master_key, new_password, is_owner=False):
    data = load_accounts()
    if target_user not in data["users"]:
        print("Користувача не знайдено.")
        return False
    user_data = data["users"][target_user]
    totp_secret = None
    if not is_owner and user_data.get("totp") and current_master_key:
        totp_secret = open_totp_secret(user_data["totp"], current_master_key, target_user)
    new_salt = secrets.token_hex(SALT_BYTES)
    new_master_key = derive_master_key(new_password, new_salt)
    new_verifier = calculate_verifier(new_master_key)
    data["users"][target_user]["salt"] = new_salt
    data["users"][target_user]["verifier"] = new_verifier
    if totp_secret:
        data["users"][target_user]["totp"] = seal_totp_secret(totp_secret, new_master_key, target_user)
    elif is_owner and target_user != current_master_key:
        data["users"][target_user]["totp"] = None
        data["users"][target_user]["totp_last_counter"] = None
    save_accounts(data)
    write_audit("change-password", target_user)
    print(f"Пароль для {target_user} змінено.")
    return True


def rotate_totp_key(username, master_key):
    data = load_accounts()
    envelope = data["users"].get(username, {}).get("totp")
    if not envelope:
        print("TOTP не підключено.")
        return False
    totp_secret = open_totp_secret(envelope, master_key, username)
    if not totp_secret:
        print("Помилка розшифрування конверта. Ротація неможлива.")
        return False
    data["users"][username]["totp"] = seal_totp_secret(totp_secret, master_key, username)
    save_accounts(data)
    write_audit("rotate-key", username)
    print(f"Ключі конверта (DEK, KEK salt, nonces) для {username} успішно оновлено.")
    return True


def handle_failed_login(data, user_data, username, current_time):
    user_data["failed_count"] += 1
    if user_data["failed_count"] >= 5:
        user_data["lock_level"] += 1
        lock_minutes = min(5 * (2 ** (user_data["lock_level"] - 1)), 60)
        user_data["locked_until"] = current_time + (lock_minutes * 60)
        user_data["failed_count"] = 0
        write_audit(f"lockout:{lock_minutes * 60}s", username)
    save_accounts(data)


def authenticate_user(username, password):
    # Тепер виклик load_accounts() одразу перевірятиме HMAC
    try:
        data = load_accounts()
    except SystemExit:
        return False, "Автентифікацію відхилено через порушення цілісності бази.", None

    user_data = data["users"].get(username)
    current_time = time.time()

    if not user_data:
        dummy_salt = "0" * (SALT_BYTES * 2)
        derive_master_key(password, dummy_salt)
        write_audit("login-fail:no-such-user", username)
        return False, "Автентифікацію відхилено.", None

    if user_data["locked_until"] > current_time:
        write_audit("login-fail:locked", username)
        return False, "Автентифікацію відхилено.", None

    master_key = derive_master_key(password, user_data["salt"])
    expected_verifier = user_data["verifier"]
    actual_verifier = calculate_verifier(master_key)

    if hmac.compare_digest(expected_verifier, actual_verifier):
        write_audit("login-password-ok", username)
        has_totp = user_data.get("totp") is not None
        if not has_totp:
            user_data["failed_count"] = 0
            user_data["lock_level"] = 0
            user_data["locked_until"] = 0
            save_accounts(data)
            write_audit("login-ok", username)
        return True, user_data["roles"], master_key
    else:
        handle_failed_login(data, user_data, username, current_time)
        write_audit("login-fail:bad-credentials", username)
        return False, "Автентифікацію відхилено.", None