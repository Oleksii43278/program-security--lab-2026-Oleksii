import sys
import getpass
import re
import time
import os
import subprocess
from accounts import (init_accounts_file, add_user, authenticate_user, write_audit,
                      get_users_list, set_user_role, change_password, rotate_totp_key,
                      get_totp_envelope, check_totp_replay, save_totp_envelope,
                      handle_failed_login, load_accounts, ACCOUNTS_FILE)
from authz import authorize
from crypto import generate_totp_secret, get_totp_token, seal_totp_secret, open_totp_secret
from integrity import build_manifest, sign_manifest, verify_manifest, MANIFEST_FILE

last_stepup_time = 0.0
session_master_key = None
# Зберігаємо час останньої генерації маніфесту в сесії
last_manifest_time = 0.0


def is_valid_username(username):
    return bool(re.match(r"^[A-Za-z0-9_.-]{1,32}$", username))


def cmd_init():
    init_accounts_file()


def get_git_state():
    """Отримує поточний стан git репозиторію."""
    try:
        branch = subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"],
                                         stderr=subprocess.DEVNULL).decode().strip()
        status = subprocess.check_output(["git", "status", "--porcelain"], stderr=subprocess.DEVNULL).decode().strip()
        is_dirty = bool(status)
        return {"branch": branch, "is_dirty": is_dirty}
    except Exception:
        return {"branch": "unknown", "is_dirty": True}


def do_stepup(username):
    global last_stepup_time, session_master_key
    print("Критична операція потребує повторного підтвердження пароля.")
    password = getpass.getpass("Пароль: ")
    success, _, m_key = authenticate_user(username, password)
    if success:
        last_stepup_time = time.time()
        session_master_key = m_key
        write_audit("stepup-ok", username)
        return True
    else:
        write_audit("stepup-fail", username)
        return False


def guard(roles, operation, target_user=None, current_user=None, repo_state=None):
    global last_stepup_time
    age = time.time() - last_stepup_time

    decision = authorize(roles, operation, target_user, current_user, age, repo_state)

    if not decision.allow and "stepup-required" in decision.reason:
        if do_stepup(current_user):
            age = 0.0
            decision = authorize(roles, operation, target_user, current_user, age, repo_state)

    if decision.allow:
        write_audit(f"authz-allow:{operation}", current_user)
        return True
    else:
        write_audit(decision.reason, current_user)
        return False


def check_totp(username, envelope, master_key):
    secret = open_totp_secret(envelope, master_key, username)
    if not secret:
        write_audit("login-fail:totp-envelope-error", username)
        print("Помилка розпечатування конверта TOTP.")
        return False

    code_input = input("Код TOTP: ").strip()
    expected_code, step = get_totp_token(secret)

    if code_input == expected_code:
        if not check_totp_replay(username, step):
            write_audit("login-fail:totp-replay", username)
            print("Цей код вже використано (replay). Зачекайте нового.")
            return False
        write_audit("login-totp-ok", username)
        return True
    else:
        write_audit("login-fail:totp-bad-code", username)
        print("Автентифікацію відхилено.")
        return False


def run_session(username, roles):
    global last_stepup_time, last_manifest_time
    last_stepup_time = time.time()

    envelope = get_totp_envelope(username)
    totp_status = "підключено" if envelope else "не підключено"

    print(f"Вхід виконано як {username} (ролі: {', '.join(roles)}). help — команди.")

    session_start = time.time()
    last_activity = session_start
    IDLE_TIMEOUT = 600
    ABSOLUTE_TIMEOUT = 3600

    while True:
        current_time = time.time()
        idle_time = current_time - last_activity
        absolute_time = current_time - session_start

        if idle_time > IDLE_TIMEOUT:
            print("\nСесію завершено через неактивність.")
            write_audit("session-timeout:idle", username)
            break
        if absolute_time > ABSOLUTE_TIMEOUT:
            print("\nАбсолютний час сесії вичерпано.")
            write_audit("session-timeout:absolute", username)
            break

        try:
            cmd_line = input(f"drs:{username}> ").strip().split()
            if not cmd_line:
                continue

            last_activity = time.time()
            cmd = cmd_line[0].lower()
            args = cmd_line[1:]

            write_audit(f"cmd:{cmd}", username)

            if cmd == "help":
                print("Команди: help | whoami | status | exit")
                print("Керування: list-users | add-user [імя] [роль] | set-role [імя] [роль]")
                print("Безпека:   passwd [імя] | enroll-totp | rotate-key")
                print("Реліз:     build-manifest [тека] | sign [тека] | verify [тека]")

            elif cmd == "whoami":
                print(f"{username} \t ролі: {', '.join(roles)}")
                print(f"Другий фактор: TOTP {totp_status}")

            elif cmd == "status":
                idle_remaining = int(IDLE_TIMEOUT - idle_time)
                abs_remaining = int(ABSOLUTE_TIMEOUT - absolute_time)
                stepup_age = int(time.time() - last_stepup_time)
                print(
                    f"Сесія активна. Простій: {idle_remaining} с; граничний: {abs_remaining} с; підтвердження: {stepup_age} с тому.")

            elif cmd == "exit":
                print("Вихід із сесії.")
                write_audit("session-exit", username)
                break

            elif cmd == "list-users":
                if guard(roles, "list-users", current_user=username):
                    users = get_users_list()
                    for u, r in users.items():
                        print(f"  {u:15} {', '.join(r)}")

            elif cmd == "add-user":
                if len(args) < 2:
                    print("Використання: add-user [імя] [роль]")
                    continue
                if guard(roles, "add-user", target_user=args[0], current_user=username):
                    pwd = getpass.getpass("Пароль: ")
                    pwd2 = getpass.getpass("Повторіть: ")
                    if pwd == pwd2:
                        add_user(args[0], pwd, args[1])
                    else:
                        print("Паролі не збігаються.")

            elif cmd == "set-role":
                if len(args) < 2:
                    continue
                if guard(roles, "set-role", target_user=args[0], current_user=username):
                    set_user_role(args[0], args[1])

            elif cmd == "passwd":
                if len(args) < 1:
                    continue
                if guard(roles, "passwd", target_user=args[0], current_user=username):
                    pwd = getpass.getpass(f"Новий пароль: ")
                    pwd2 = getpass.getpass("Повторіть: ")
                    if pwd == pwd2:
                        is_owner = "owner" in roles
                        m_key = session_master_key if args[0] == username else None
                        change_password(args[0], m_key, pwd, is_owner=is_owner)
                    else:
                        print("Паролі не збігаються.")

            elif cmd == "enroll-totp":
                if guard(roles, "enroll-totp", target_user=username, current_user=username):
                    secret = generate_totp_secret()
                    print(
                        f"\notpauth://totp/drs_release:{username}?secret={secret}&issuer=drs_release&algorithm=SHA1&digits=6&period=30\n")
                    if input("Код: ").strip() == get_totp_token(secret)[0]:
                        envelope = seal_totp_secret(secret, session_master_key, username)
                        save_totp_envelope(username, envelope, get_totp_token(secret)[1])
                        totp_status = "підключено"
                        print("TOTP підключено.")

            elif cmd == "rotate-key":
                if guard(roles, "rotate-key", current_user=username):
                    rotate_totp_key(username, session_master_key)

            elif cmd == "build-manifest":
                if len(args) < 1:
                    print("Вкажіть теку.")
                    continue
                if guard(roles, "build-manifest", current_user=username):
                    target_dir = args[0]
                    if not os.path.isdir(target_dir):
                        print("Теку не знайдено.")
                        continue
                    count = build_manifest(target_dir)
                    last_manifest_time = time.time()
                    write_audit(f"build-manifest:{count}", username)
                    print(f"Маніфест {MANIFEST_FILE} створено: {count} файл(ів).")

            elif cmd == "sign":
                if len(args) < 1:
                    print("Вкажіть теку.")
                    continue

                target_dir = args[0]
                manifest_path = os.path.join(target_dir, MANIFEST_FILE)

                # Перевіряємо, чи маніфест не застарілий
                if os.path.exists(manifest_path):
                    if os.path.getmtime(manifest_path) > last_manifest_time:
                        write_audit("sign-deny:stale-manifest", username)
                        print("Маніфест не відповідає теці (змінено файли) — спершу виконайте build-manifest.")
                        continue

                repo_state = get_git_state()
                if guard(roles, "sign", current_user=username, repo_state=repo_state):
                    ok, msg = sign_manifest(target_dir)
                    if ok:
                        write_audit("sign:ok", username)
                        print(f"{msg} (branch={repo_state['branch']}, dirty={repo_state['is_dirty']})")
                    else:
                        write_audit(f"sign:error:{msg}", username)
                        print(f"Помилка: {msg}")
                else:
                    print("Операцію відхилено. (Переконайтеся, що ви на гілці master і немає незакомічених змін).")

            elif cmd == "verify":
                if len(args) < 1:
                    print("Вкажіть теку.")
                    continue
                if guard(roles, "verify", current_user=username):
                    ok, errs = verify_manifest(args[0])
                    if ok:
                        write_audit("verify:ok", username)
                        print(errs[0])
                    else:
                        write_audit("verify:fail", username)
                        print("ПЕРЕВІРКА НЕ ПРОЙДЕНА:")
                        for e in errs:
                            print(f"  - {e}")

            else:
                print(f"Невідома команда: {cmd}")

        except (KeyboardInterrupt, EOFError):
            print("\nВихід із сесії.")
            write_audit("session-exit:interrupt", username)
            break


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Використання: python drs_release.py [команда] [аргументи]")
        sys.exit(1)

    command = sys.argv[1]

    if command == "init":
        cmd_init()
    elif command == "add-user":
        users = get_users_list()
        if users:
            print("Облікові записи вже існують. Додавання — лише в сесії.")
        else:
            if len(sys.argv) < 3:
                sys.exit(1)
            role = sys.argv[3] if len(sys.argv) > 3 else "owner"
            pwd = getpass.getpass("Пароль: ")
            if pwd == getpass.getpass("Повторіть: "):
                add_user(sys.argv[2], pwd, role)
                print(f"Створено першого користувача (бутстрап).")

    elif command == "login":
        if len(sys.argv) < 3:
            sys.exit(1)
        username = sys.argv[2]
        pwd = getpass.getpass("Пароль: ")

        # Перехоплюємо SystemExit на випадок, якщо HMAC недійсний
        try:
            success, roles_or_msg, master_key = authenticate_user(username, pwd)
        except SystemExit as e:
            sys.exit(e.code)

        if success:
            session_master_key = master_key
            envelope = get_totp_envelope(username)
            if envelope:
                if check_totp(username, envelope, master_key):
                    data = load_accounts()
                    data["users"][username]["failed_count"] = 0
                    data["users"][username]["lock_level"] = 0
                    data["users"][username]["locked_until"] = 0
                    from accounts import save_accounts

                    save_accounts(data)
                    write_audit("login-ok", username)
                    run_session(username, roles_or_msg)
                else:
                    data = load_accounts()
                    handle_failed_login(data, data["users"][username], username, time.time())
            else:
                write_audit("login-ok", username)
                run_session(username, roles_or_msg)
        else:
            print(roles_or_msg)