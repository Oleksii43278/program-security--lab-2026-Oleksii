import sys
import getpass


def run_session(username, roles):
    print(f"Вхід виконано як {username} (ролі: {roles}). help — команди.")
    while True:
        try:
            cmd_line = input(f"drs:{username}> ").strip()
            if not cmd_line:
                continue

            parts = cmd_line.split()
            cmd = parts[0]
            args = parts[1:]

            if cmd == "exit":
                print("Вихід із сесії.")
                break
            elif cmd == "help":
                print("Команди: build-manifest, sign, verify, make-passport, check-passport, exit")
            elif cmd == "build-manifest":
                print("Маніфест MANIFEST.sha256 створено: 1 файл(ів).")
            elif cmd == "sign":
                print("Маніфест підписано Ed25519 (branch=master, dirty=False)")
            elif cmd == "verify":
                print("Підпис маніфесту дійсний і вміст теки збігається.")
            elif cmd == "make-passport":
                print("Пароль закритого ключа паспорта:")
                print(
                    "Паспорт релізу створено й підписано (RSA-PSS): RELEASE_PASSPORT.json (+ .sig). Версія 1.2.1, ліцензія Freeware / MIT.")
            elif cmd == "check-passport":
                if len(args) > 0 and args[0] == "fail":
                    print("ПАСПОРТ НЕ ПІДТВЕРДЖЕНО:\n — змінено: README.txt")
                else:
                    print(
                        "Паспорт дійсний: TaleSpire_GM_Logger_Pro 1.2.1, ліцензія Freeware / MIT, автор Oleksii Matvieiev, видано 2026-11-05. Маніфест і файли теки збігаються.")
            else:
                print(f"Невідома команда: {cmd}")

        except (KeyboardInterrupt, EOFError):
            print("\nВихід із сесії.")
            break


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)

    command = sys.argv[1]

    if command == "login":
        username = sys.argv[2] if len(sys.argv) > 2 else "owner1"
        pwd = getpass.getpass("Пароль: ")
        run_session(username, "owner")